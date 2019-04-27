import base64
import ssl
import urllib.request
import json
import requests
from urllib3.exceptions import InsecureRequestWarning
from time import sleep

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

        transport_zone_id = self.create_transport_zone()
        print(transport_zone_id)
        # transport_zone_id = self.get_transport_zones()['allScopes'][0]['objectId']

        no_controllers = 1
        for x in range(1, (no_controllers + 1)):
            controller_name = '{}0{}'.format(config['NSX']['CONTROLLER_PREFIX'], x)

            controller = self.deploy_controller(controller_name,
                                                controller_ip_pool_id)
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

        print(self.create_logical_switch('Transit', transport_zone_id))
        print(self.create_logical_switch('DLR-HA', transport_zone_id))
        print(self.create_logical_switch('Web-LS', transport_zone_id))
        print(self.create_logical_switch('App-LS', transport_zone_id))
        print(self.create_logical_switch('DB-LS', transport_zone_id))

        print(self.deploy_dlr())
        print(self.deploy_esg())

        edge_id = self.get_edge(self.esg_name)
        dlr_id = self.get_edge(self.dlr_name)

        self.config_edge_routing(edge_id)
        self.config_edge_routing(dlr_id)

        return

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

    def nsx_post_xml(self, api_url, data):
        url = 'https://' + self.nsx_host + api_url

        headers = {'Authorization': self.authorizationField,
                   'Content-Type': 'application/xml'
                   }

        response = requests.request('POST',
                                    url,
                                    data=data,
                                    headers=headers,
                                    verify=False)

        return response.text

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

    def create_quick_logical_switch(self, ls_name):
        transport_zone_id = self.get_transport_zones()['allScopes'][0]['objectId']
        print(self.create_logical_switch(ls_name, transport_zone_id))

    def deploy_dlr(self):
        dlr_ha_mgmt_ls = self.get_logical_switch('DLR-HA')
        transit_ls = self.get_logical_switch('Transit')
        web_ls = self.get_logical_switch('Web-LS')
        data = "<edge>\n\
    <datacenterMoid>{}</datacenterMoid>\n\
    <name>{}</name>\n\
    <type>distributedRouter</type>\n\
    <appliances>\n\
        <appliance>\n\
            <resourcePoolId>{}</resourcePoolId>\n\
            <datastoreId>{}</datastoreId>\n\
        </appliance>\n\
    </appliances>\n\
    <mgmtInterface>\n\
        <connectedToId>{}</connectedToId>\n\
        <addressGroups>\n\
            <addressGroup>\n\
                <primaryAddress>169.254.254.1</primaryAddress>\n\
                <subnetMask>255.255.255.252</subnetMask>\n\
            </addressGroup>\n\
        </addressGroups>\n\
    </mgmtInterface>\n\
    <interfaces>\n\
        <interface>\n\
            <type>uplink</type>\n\
            <name>Transit-LIF</name>\n\
            <mtu>1500</mtu>\n\
            <isConnected>true</isConnected>\n\
            <addressGroups>\n\
                <addressGroup>\n\
                    <primaryAddress>{}</primaryAddress>\n\
                    <subnetMask>255.255.255.248</subnetMask>\n\
                </addressGroup>\n\
            </addressGroups>\n\
            <connectedToId>{}</connectedToId>\n\
        </interface>\n\
        <interface>\n\
            <type>internal</type>\n\
            <name>Web-LIF</name>\n\
            <mtu>1500</mtu>\n\
            <isConnected>true</isConnected>\n\
            <addressGroups>\n\
                <addressGroup>\n\
                    <primaryAddress>{}</primaryAddress>\n\
                    <subnetMask>255.255.255.0</subnetMask>\n\
                </addressGroup>\n\
            </addressGroups>\n\
            <connectedToId>{}</connectedToId>\n\
        </interface>\n\
    </interfaces>\n\
</edge>".format(self.datacenter_id,
                self.dlr_name,
                self.cluster_id,
                self.datastore_id,
                dlr_ha_mgmt_ls,
                self.dlr_fwd_ip,
                transit_ls,
                self.web_lif_ip,
                web_ls)

        api_data = self.nsx_post_xml('/api/4.0/edges',
                                     data)
        return api_data

    def deploy_esg(self):
        transit_ls = self.get_logical_switch('Transit')
        data = "<edge>\n\
    <datacenterMoid>{}</datacenterMoid>\n\
    <name>{}</name>\n\
    <fqdn>{}</fqdn>\n\
    <appliances>\n\
        <applianceSize>compact</applianceSize>\n\
        <appliance>\n\
            <resourcePoolId>{}</resourcePoolId>\n\
            <datastoreId>{}</datastoreId>\n\
        </appliance>\n\
    </appliances>\n\
    <vnics>\n\
        <vnic>\n\
            <index>0</index>\n\
            <label>External</label>\n\
            <type>uplink</type>\n\
            <portgroupId>{}</portgroupId>\n\
            <addressGroups>\n\
                <addressGroup>\n\
                    <primaryAddress>{}</primaryAddress>\n\
                    <secondaryAddresses>\n\
                        <ipAddress>{}</ipAddress>\n\
                    </secondaryAddresses>\n\
                    <subnetMask>255.255.255.0</subnetMask>\n\
                </addressGroup>\n\
            </addressGroups>\n\
            <isConnected>true</isConnected>\n\
        </vnic>\n\
        <vnic>\n\
            <index>1</index>\n\
            <label>Transit</label>\n\
            <type>internal</type>\n\
            <portgroupId>{}</portgroupId>\n\
            <addressGroups>\n\
                <addressGroup>\n\
                    <primaryAddress>{}</primaryAddress>\n\
                    <subnetPrefixLength>29</subnetPrefixLength>\n\
                </addressGroup>\n\
            </addressGroups>\n\
            <isConnected>true</isConnected>\n\
        </vnic>\n\
    </vnics>\n\
    <cliSettings>\n\
        <userName>admin</userName>\n\
        <password>{}</password>\n\
        <remoteAccess>false</remoteAccess>\n\
    </cliSettings>\n\
</edge>".format(self.datacenter_id,
                self.esg_name,
                self.esg_name,
                self.cluster_id,
                self.datastore_id,
                self.vm_network_id,
                self.esg_external_ip,
                self.esg_secondary_ip,
                transit_ls,
                self.esg_transit_ip,
                self.infra_password)

        api_data = self.nsx_post_xml('/api/4.0/edges',
                                     data)
        return api_data

    def get_edges(self):
        return self.get_json_api_data('/api/4.0/edges')

    def get_edge(self, name):
        for edge in self.get_edges()['edgePage']['data']:
            if edge['name'] == name:
                return edge['objectId']

    def get_edge_config(self, edge_id):
        return self.get_json_api_data('/api/4.0/edges/{}'.format(edge_id))

    def remove_config_versions(self, config):
        # Removes the 'version' entries from an Edge's config to
        # allow updating and sending it back
        if not isinstance(config, (dict, list)):
            return config
        if isinstance(config, list):
            return [self.remove_config_versions(v) for v in config]
        return {k: self.remove_config_versions(v) for k, v in config.items()
                if k not in {'version'}}

    def config_edge_routing(self, edge_id):
        esg = False
        edge_config = self.get_edge_config(edge_id)

        if edge_config['type'] == 'gatewayServices':
            esg = True
            router_id = self.esg_external_ip
        elif edge_config['type'] == 'distributedRouter':
            router_id = self.dlr_ctrl_ip

        new_config = self.remove_config_versions(edge_config)

        for index, feature in enumerate(new_config['featureConfigs']['features']):
            if esg:
                if feature['featureType'] == 'firewall_4.0':
                    new_config['featureConfigs']['features'][index]['defaultPolicy']['action'] = "accept"

            if feature['featureType'] == 'routing_4.0':
                new_config['featureConfigs']['features'][index]['ospf']['enabled'] = "true"
                new_config['featureConfigs']['features'][index]['ospf']['ospfAreas']['ospfAreas'][0]['areaId'] = self.internal_ospf_area
                new_config['featureConfigs']['features'][index]['routingGlobalConfig']['routerId'] = router_id
                
                if esg:
                    new_config['featureConfigs']['features'][index]['ospf']['ospfInterfaces']['ospfInterfaces'].append({
                      "vnic": 0,
                      "areaId": 0,
                      "helloInterval": 10,
                      "deadInterval": 40,
                      "priority": 128,
                      "cost": 1,
                      "mtuIgnore": "false"
                    })
                    new_config['featureConfigs']['features'][index]['ospf']['ospfInterfaces']['ospfInterfaces'].append({
                      "vnic": 1,
                      "areaId": self.internal_ospf_area,
                      "helloInterval": 10,
                      "deadInterval": 40,
                      "priority": 128,
                      "cost": 1,
                      "mtuIgnore": "false"
                    })
                else:
                    new_config['featureConfigs']['features'][index]['ospf']['protocolAddress'] = self.dlr_ctrl_ip
                    new_config['featureConfigs']['features'][index]['ospf']['forwardingAddress'] = self.dlr_fwd_ip
                    new_config['featureConfigs']['features'][index]['ospf']['ospfInterfaces']['ospfInterfaces'].append({
                      "vnic": 2,
                      "areaId": self.internal_ospf_area,
                      "helloInterval": 10,
                      "deadInterval": 40,
                      "priority": 128,
                      "cost": 1,
                      "mtuIgnore": "false"
                    })

        json_new_config = json.dumps(new_config)

        print(self.nsx_send_json('/api/4.0/edges/{}'.format(edge_id),
                                 json_new_config,
                                 'PUT'))

    def get_host_comm_status(self, host_id):
        return self.get_json_api_data('/api/2.0/vdn/inventory/host/{}/connection/status'.format(host_id))


vc = Vcenter()
nsx = Nsx(vc)

print(nsx.get_nsx_info())
nsx.deploy()
