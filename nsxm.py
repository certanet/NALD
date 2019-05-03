import base64
import ssl
import urllib.request
import json
import requests
from urllib3.exceptions import InsecureRequestWarning
from time import sleep
from jinja2 import Environment, FileSystemLoader

from vcenter import Vcenter, config
from license import VcenterLicense

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Nsx():
    def __init__(self, vcenter):
        # Initialise vCenter objects:
        self.vcenter = vcenter
        self.cluster_id = self.vcenter.list_all_clusters()[0]._moId
        self.dvs_id = self.vcenter.list_all_dvs()[0]._moId
        self.datastore_id = self.vcenter.list_all_datastores()[0]._moId
        self.vm_network_id = self.vcenter.get_network('VM Network')._moId
        self.datacenter_id = self.vcenter.get_datacenter()._moId

        # Initialise config:
        self.nsx_host = config['NSX']['HOST']
        self.nsx_user = config['NSX']['USER']
        self.nsx_pass = config['NSX']['PASSWORD']
        self.infra_password = config['NSX']['INFRA_PASSWORD']

        self.num_controllers = config['NSX']['NUM_CONTROLLERS']

        self.web_lif_ip = config['NSX']['WEB_LS_LIF']

        self.dlr_name = config['NSX']['DLR_NAME']
        self.dlr_fwd_ip = config['NSX']['DLR_FORWARDING_IP']
        self.dlr_ctrl_ip = config['NSX']['DLR_PROTOCOL_IP']
        self.internal_ospf_area = int(config['NSX']['DLR_OSPF_AREA'])

        self.esg_name = config['NSX']['ESG_NAME']
        self.esg_external_ip = config['NSX']['ESG_EX_IP']
        self.esg_secondary_ip = config['NSX']['ESG_EX_IP2']
        self.esg_transit_ip = config['NSX']['ESG_IN_IP']

        self.dns_domain = config['NSX']['DNS_DOMAIN']
        self.dns_server = config['NSX']['DNS_SERVER']

        self.nsx_setup()

    def deploy(self):
        VcenterLicense(self.vcenter).apply_nsx_lic()

        vc_thumbprint_sha1 = json.loads(self.configure_nsx_vc_sso().text)['details']
        if json.loads(self.configure_nsx_vc_sso(vc_thumbprint_sha1).text)['status']:
            print('Configured NSX-VC SSO!')

        vc_thumbprint_sha256 = json.loads(self.configure_nsx_vc_inventory().text)['details']
        self.configure_nsx_vc_inventory(vc_thumbprint_sha256)

        if self.get_nsx_vc_inventory()['connected']:
            print('vCenter Inventory is Connected!')

        if self.create_ip_pool('VTEP_POOL',
                               config['NSX']['VTEP_POOL_START'],
                               config['NSX']['VTEP_POOL_END'],
                               config['NSX']['VTEP_POOL_MASK'],
                               config['NSX']['VTEP_POOL_GATEWAY']).status_code == 201:
            print('Created VTEP IP Pool!')

        if self.create_ip_pool('CONTROLLER_POOL',
                               config['NSX']['CONTROLLER_POOL_START'],
                               config['NSX']['CONTROLLER_POOL_END'],
                               config['NSX']['CONTROLLER_POOL_MASK'],
                               config['NSX']['CONTROLLER_POOL_GATEWAY']).status_code == 201:
            print('Created Controller IP Pool!')

        if self.create_segment_id(config['NSX']['SEGMENT_ID_START'],
                                     config['NSX']['SEGMENT_ID_END']).status_code == 201:
            print('Created Segment ID Pool!')

        vtep_ip_pool_id = self.get_ip_pool_id_by_name('VTEP_POOL')
        controller_ip_pool_id = self.get_ip_pool_id_by_name('CONTROLLER_POOL')

        print(self.configure_vxlan(vtep_ip_pool_id))
        sleep(10)

        status, hp, rabbit, fw = False, False, False, False
        while not status:
            prep_status = self.get_host_prep_status()
            for feature in prep_status['statuses'][0]['featureStatuses']:
                if feature['featureId'] == 'com.vmware.vshield.vsm.nwfabric.hostPrep':
                    if feature['status'] == 'GREEN':
                        hp = True
                    else:
                        print(feature['status'], end='/')
                elif feature['featureId'] == 'com.vmware.vshield.vsm.messagingInfra':
                    if feature['status'] == 'GREEN':
                        rabbit = True
                    else:
                        print(feature['status'], end='/')
                elif feature['featureId'] == 'com.vmware.vshield.firewall':
                    if feature['status'] == 'GREEN':
                        fw = True
                    else:
                        print(feature['status'])
                        sleep(5)
            if hp and rabbit and fw:
                status = True

        ready_hosts = 0
        num_hosts = len(self.vcenter.list_hosts_in_cluster(self.cluster_id))
        while ready_hosts < num_hosts:
            for host in self.vcenter.list_hosts_in_cluster(self.cluster_id):
                comm_status = self.get_host_comm_status(host._moId)
                if comm_status['nsxMgrToControlPlaneAgentConn'] == 'UP':
                    ready_hosts += 1
                else:
                    print('Host: {} Status: {}'.format(host,
                                                       comm_status['nsxMgrToControlPlaneAgentConn']))
                    sleep(5)

        transport_zone = self.create_transport_zone()
        if transport_zone.status_code == 201:
            print('Created Transport Zone!')
        transport_zone_id = transport_zone.text

        for x in range(1, (self.num_controllers + 1)):
            controller_name = '{}0{}'.format(config['NSX']['CONTROLLER_PREFIX'], x)

            controller = self.deploy_controller(controller_name,
                                                controller_ip_pool_id).text
            print(self.get_controller_job_status(controller))

            while True:
                status = self.get_controller_job_status(controller)
                print(status)
                sleep(10)
                # Checks if deploy is complete and prints the controller VM ID:
                # Examples:
                #    {'progress': 88, 'status': 'PushingFile'}
                #    {'vmId': 'vm-696', 'status': 'WaitingForToolRunning'}
                #    {'vmId': 'vm-696', 'status': 'Success'}
                if status['status'] == 'Success':
                    print(status['vmId'])
                    break

        # transport_zone_id = self.get_transport_zones()['allScopes'][0]['objectId']
        logical_switches = ['Transit', 'DLR-HA', 'Web-LS', 'App-LS', 'DB-LS']

        for ls in logical_switches:
            if self.create_logical_switch('Transit', transport_zone_id).status_code == 201:
                print('Created Logical Switch "%s"' % ls)

        print(self.deploy_dlr().text)
        print(self.deploy_esg().text)

    def nsx_setup(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        httpsHandler = urllib.request.HTTPSHandler(context=context)

        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        authHandler = urllib.request.HTTPBasicAuthHandler(manager)

        opener = urllib.request.build_opener(httpsHandler, authHandler)
        urllib.request.install_opener(opener)

        basicAuthString = '%s:%s' % (self.nsx_user, self.nsx_pass)
        field = base64.b64encode(basicAuthString.encode('ascii'))
        self.authorizationField = 'Basic %s' % str(field, 'utf-8')

    def nsx_return_json(self, url):
        request = urllib.request.Request(url,
                                         headers={'Authorization': self.authorizationField,
                                                  'Accept': 'application/json'})
        response = urllib.request.urlopen(request)

        json_dict = json.loads(response.read().decode())
        return json_dict

    def get_json_api_data(self, api_url):
        full_url = 'https://' + self.nsx_host + api_url
        response = self.nsx_return_json(full_url)

        return response

    def nsx_send_json(self, api_url, data, method='POST'):
        # Method could be POST/PUT
        url = 'https://' + self.nsx_host + api_url

        headers = {'Authorization': self.authorizationField,
                   'Accept': 'application/json',
                   'Content-Type': 'application/json'
                   }

        response = requests.request(method,
                                    url,
                                    data=data,
                                    headers=headers,
                                    verify=False)

        return response

    def get_nsx_info(self):
        return self.get_json_api_data('/api/1.0/appliance-management/global/info')

    def get_host_prep_status(self):
        return self.get_json_api_data('/api/2.0/nwfabric/status?resource={}'.format(self.cluster_id))

    def get_job_status(self, job_id):
        return self.get_json_api_data('/api/2.0/services/taskservice/job/{}'.format(job_id))

    def get_host_comm_status(self, host_id):
        return self.get_json_api_data('/api/2.0/vdn/inventory/host/{}/connection/status'.format(host_id))

    def configure_nsx_vc_sso(self, vc_thumbprint_sha1=''):
        sso_lookup_url = 'https://{}:443/lookupservice/sdk'.format(self.vcenter.ip)

        sso_config = {'ssoLookupServiceUrl': sso_lookup_url,
                      'ssoAdminUsername': self.vcenter.user,
                      'ssoAdminUserpassword': self.vcenter.password,
                      'certificateThumbprint': vc_thumbprint_sha1
                      }

        return self.nsx_send_json('/api/2.0/services/ssoconfig',
                                  json.dumps(sso_config))

    def get_nsx_vc_sso(self):
        return self.get_json_api_data('/api/2.0/services/ssoconfig/status')

    def configure_nsx_vc_inventory(self, vc_thumbprint_sha256=''):
        vc_config = {'ipAddress': self.vcenter.ip,
                     'userName': self.vcenter.user,
                     'password': self.vcenter.password,
                     'certificateThumbprint': vc_thumbprint_sha256
                     }

        return self.nsx_send_json('/api/2.0/services/vcconfig',
                                  json.dumps(vc_config),
                                  'PUT')

    def get_nsx_vc_inventory(self):
        return self.get_json_api_data('/api/2.0/services/vcconfig/status')

    def create_ip_pool(self, name, start, end, prefix, gateway):
        ip_pool = {'name': name,
                   'prefixLength': prefix,
                   'gateway': gateway,
                   'dnsSuffix': self.dns_domain,
                   'dnsServer1': self.dns_server,
                   'ipRanges': [
                       {'startAddress': start,
                        'endAddress': end
                        }
                        ]
                   }

        return self.nsx_send_json('/api/2.0/services/ipam/pools/scope/globalroot-0',
                                  json.dumps(ip_pool))

    def get_ip_pools(self):
        return self.get_json_api_data('/api/2.0/services/ipam/pools/scope/globalroot-0')

    def get_ip_pool_id_by_name(self, pool_name):
        ip_pool_id = None

        for pool in self.get_ip_pools()['ipAddressPools']:
            if pool['name'] == pool_name:
                ip_pool_id = pool['objectId']
                break

        return ip_pool_id

    def configure_vxlan(self, ip_pool_id):
        vxlan_config = {"featureId": "com.vmware.vshield.vsm.vxlan",
                        "resourceConfigs": [
                            {
                                "resourceId": self.cluster_id,
                                "configSpec": {
                                    "class": "clusterMappingSpec",
                                    "switchObj": {
                                        "objectId": self.dvs_id
                                    },
                                    "vlan": "0",
                                    "vmknicCount": "1",
                                    "ipPoolId": ip_pool_id
                                }
                            },
                            {
                                "resourceId": self.dvs_id,
                                "configSpec": {
                                    "class": "vdsContext",
                                    "switchObj": {
                                        "objectId": self.dvs_id
                                    },
                                    "mtu": "1600",
                                    "teaming": "FAILOVER_ORDER"
                                }
                            }
                        ]
                        }

        return self.nsx_send_json('/api/2.0/nwfabric/configure',
                                  json.dumps(vxlan_config))

    def create_segment_id(self, range_start, range_end):
        segment_id = {'name': 'NALD Segment',
                      'begin': range_start,
                      'end': range_end
                      }

        return self.nsx_send_json('/api/2.0/vdn/config/segments',
                                  json.dumps(segment_id))

    def create_transport_zone(self):
        transport_zone = {
                          'name': 'NALD-Transport-Zone',
                          'clusters': {
                            'clusters': [
                              {
                                'cluster': {
                                  'objectId': self.cluster_id
                                }
                              }
                            ]
                          },
                          'controlPlaneMode': 'UNICAST_MODE'
                        }

        return self.nsx_send_json('/api/2.0/vdn/scopes',
                                  json.dumps(transport_zone))

    def get_transport_zones(self):
        return self.get_json_api_data('/api/2.0/vdn/scopes')

    def deploy_controller(self, name, ip_pool_id):
        controller = {"name": name,
                      "ipPoolId": ip_pool_id,
                      "resourcePoolId": self.cluster_id,
                      "datastoreId": self.datastore_id,
                      "networkId": self.vm_network_id,
                      "password": self.infra_password
                      }

        return self.nsx_send_json('/api/2.0/vdn/controller',
                                  json.dumps(controller))

    def get_controller_job_status(self, job_id):
        return self.get_json_api_data('/api/2.0/vdn/controller/progress/{}'.format(job_id))

    def get_logical_switches(self):
        return self.get_json_api_data('/api/2.0/vdn/virtualwires')

    def get_logical_switch(self, name):
        for switch in self.get_logical_switches()['dataPage']['data']:
            if switch['name'] == name:
                return switch['objectId']

    def create_logical_switch(self, ls_name, transport_zone_id, ls_desc=''):
        logical_switch = {'name': ls_name,
                          'description': ls_desc,
                          'tenantId': 'virtual wire tenant',
                          'controlPlaneMode': 'UNICAST_MODE'
                          }

        return self.nsx_send_json('/api/2.0/vdn/scopes/{}/virtualwires'.format(transport_zone_id),
                                  json.dumps(logical_switch))

    def load_jinja_template(self, template_file, vars_dict):
        jinja_loader = Environment(loader=FileSystemLoader('templates'),
                                   trim_blocks=True,
                                   lstrip_blocks=True)
        template = jinja_loader.get_template(template_file)
        return template.render(vars_dict)

    def deploy_dlr(self):
        dlr = dict()
        dlr['nsx'] = self
        dlr['transit_ls'] = self.get_logical_switch('Transit')
        dlr['dlr_ha_mgmt_ls'] = self.get_logical_switch('DLR-HA')
        dlr['web_ls'] = self.get_logical_switch('Web-LS')

        return self.nsx_send_json('/api/4.0/edges',
                                  self.load_jinja_template('dlr.json', dlr))

    def deploy_esg(self):
        esg = dict()
        esg['nsx'] = self
        esg['transit_ls'] = self.get_logical_switch('Transit')

        return self.nsx_send_json('/api/4.0/edges',
                                  self.load_jinja_template('esg.json', esg))


vc = Vcenter()
nsx = Nsx(vc)

print(nsx.get_nsx_info())
print(nsx.deploy())
