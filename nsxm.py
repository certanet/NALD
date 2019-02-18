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
        prep_job = self.nsx_host_prep('set')
        print(self.get_job_status(prep_job))

        print(self.create_transport_zone())

        print(self.create_ip_pool('VTEP_POOL',
                                  config['NSX']['VTEP_POOL_START'],
                                  config['NSX']['VTEP_POOL_END'],
                                  config['NSX']['VTEP_POOL_MASK'],
                                  config['NSX']['VTEP_POOL_GATEWAY']))
        print(self.create_ip_pool('CONTROLLER_POOL',
                                  config['NSX']['CONTROLLER_POOL_START'],
                                  config['NSX']['CONTROLLER_POOL_END'],
                                  config['NSX']['CONTROLLER_POOL_MASK'],
                                  config['NSX']['CONTROLLER_POOL_GATEWAY']))

        print(self.create_segment_id(config['NSX']['SEGMENT_ID_START'],
                                     config['NSX']['SEGMENT_ID_END']))

        vtep_ip_pool_id = self.get_ip_pool_id_by_name('VTEP_POOL')
        controller_ip_pool_id = self.get_ip_pool_id_by_name('CONTROLLER_POOL')

        print(self.configure_vxlan(vtep_ip_pool_id))

        transport_zone_id = self.get_transport_zones()['allScopes'][0]['objectId']

        no_controllers = 1
        for x in range(1, (no_controllers + 1)):
            controller_name = '{}0{}'.format(config['NSX']['CONTROLLER_PREFIX'],x)

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
        api_data = self.nsx_return_json(full_url)

        return api_data

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
                   'Content-Type': 'application/json'
                   }

        response = requests.request(method,
                                    url,
                                    data=data,
                                    headers=headers,
                                    verify=False)

        return response

    def get_nsx_info(self):
        api_data = self.get_json_api_data('/api/1.0/appliance-management/global/info')
        return api_data

    def nsx_host_prep(self, get_set='get'):
        if get_set == 'get':
            api_data = self.get_json_api_data('/api/2.0/nwfabric/status?resource={}'.format(self.cluster_id))
        elif get_set == 'set':
            data = "<nwFabricFeatureConfig>\n\
                        <resourceConfig>\n\
                            <resourceId>{}</resourceId>\n\
                        </resourceConfig>\n\
                    </nwFabricFeatureConfig>".format(self.cluster_id)
            api_data = self.nsx_post_xml('/api/2.0/nwfabric/configure',
                                         data)
        return api_data

    def get_job_status(self, job_id):
        api_data = self.get_json_api_data('/api/2.0/services/taskservice/job/{}'.format(job_id))
        return api_data

    def create_ip_pool(self, name, start, end, prefix, gateway):
        data = "<ipamAddressPool>\n\
                    <name>{}</name>\n\
                    <prefixLength>{}</prefixLength>\n\
                    <gateway>{}</gateway>\n\
                    <dnsSuffix>{}</dnsSuffix>\n\
                    <dnsServer1>{}</dnsServer1>\n\
                    <dnsServer2></dnsServer2>\n\
                    <ipRanges>\n\
                        <ipRangeDto>\n\
                            <startAddress>{}</startAddress>\n\
                            <endAddress>{}</endAddress>\n\
                        </ipRangeDto>\n\
                    </ipRanges>\n\
                </ipamAddressPool>".format(name,
                                           prefix,
                                           gateway,
                                           self.dns_domain,
                                           self.dns_server,
                                           start,
                                           end)

        api_data = self.nsx_post_xml('/api/2.0/services/ipam/pools/scope/globalroot-0',
                                     data)
        return api_data

    def get_ip_pools(self):
        api_data = self.get_json_api_data('/api/2.0/services/ipam/pools/scope/globalroot-0')
        return api_data

    def get_ip_pool_id_by_name(self, pool_name):
        ip_pool_id = None

        for pool in self.get_ip_pools()['ipAddressPools']:
            if pool['name'] == pool_name:
                ip_pool_id = pool['objectId']
                break

        return ip_pool_id

    def configure_vxlan(self, ip_pool_id):
        data = '<nwFabricFeatureConfig>\n\
                <featureId>com.vmware.vshield.vsm.vxlan</featureId>\n\
                <resourceConfig>\n\
                <resourceId>{0}</resourceId>\n\
                <configSpec class="clusterMappingSpec">\n\
                <switch>\n\
                <objectId>{1}</objectId>\n\
                </switch>\n\
                <vlanId>0</vlanId>\n\
                <vmknicCount>1</vmknicCount>\n\
                <ipPoolId>{2}</ipPoolId>\n\
                </configSpec>\n\
                </resourceConfig>\n\
                <resourceConfig>\n\
                    <resourceId>{1}</resourceId>\n\
                    <configSpec class="vdsContext">\n\
                        <switch>\n\
                            <objectId>{1}</objectId>\n\
                        </switch>\n\
                        <mtu>1600</mtu>\n\
                        <teaming>FAILOVER_ORDER</teaming>\n\
                    </configSpec>\n\
                </resourceConfig>\n\
                </nwFabricFeatureConfig>'.format(self.cluster_id,
                                                 self.dvs_id,
                                                 ip_pool_id)
        api_data = self.nsx_post_xml('/api/2.0/nwfabric/configure',
                                     data)
        return api_data

    def create_segment_id(self, range_start, range_end):
        data = "<segmentRange>\n\
                    <name>MC Segment</name>\n\
                    <desc>Segment ID Range 1</desc>\n\
                    <begin>{}</begin>\n\
                    <end>{}</end>\n\
                </segmentRange>".format(range_start, range_end)

        api_data = self.nsx_post_xml('/api/2.0/vdn/config/segments',
                                     data)
        return api_data

    def create_transport_zone(self):
        data = "<vdnScope>\n\
                <name>MC-Transport-Zone</name>\n\
                <clusters>\n\
                    <cluster>\n\
                        <cluster>\n\
                            <objectId>{}</objectId>\n\
                        </cluster>\n\
                    </cluster>\n\
                </clusters>\n\
                <controlPlaneMode>UNICAST_MODE</controlPlaneMode>\n\
                </vdnScope>".format(self.cluster_id)

        api_data = self.nsx_post_xml('/api/2.0/vdn/scopes',
                                     data)
        return api_data

    def get_transport_zones(self):
        api_data = self.get_json_api_data('/api/2.0/vdn/scopes')
        return api_data

    def deploy_controller(self, name, ip_pool_id):
        data = "<controllerSpec>\n\
                    <name>{}</name>\n\
                    <description>NSX-Controller</description>\n\
                    <ipPoolId>{}</ipPoolId>\n\
                    <resourcePoolId>{}</resourcePoolId>\n\
                    <datastoreId>{}</datastoreId>\n\
                    <deployType>medium</deployType>\n\
                    <networkId>{}</networkId>\n\
                    <password>{}</password>\n\
                </controllerSpec>".format(name,
                                          ip_pool_id,
                                          self.cluster_id,
                                          self.datastore_id,
                                          self.vm_network_id,
                                          self.infra_password)

        api_data = self.nsx_post_xml('/api/2.0/vdn/controller',
                                     data)
        return api_data

    def get_controller_job_status(self, job_id):
        api_data = self.get_json_api_data('/api/2.0/vdn/controller/progress/{}'.format(job_id))
        return api_data

    def get_logical_switches(self):
        api_data = self.get_json_api_data('/api/2.0/vdn/virtualwires')
        return api_data

    def get_logical_switch(self, name):
        for switch in self.get_logical_switches()['dataPage']['data']:
            if switch['name'] == name:
                return switch['objectId']

    def create_logical_switch(self, ls_name, transport_zone_id, ls_desc=''):
        data = "<virtualWireCreateSpec>\n\
                    <name>{}</name>\n\
                    <description>{}</description>\n\
                    <tenantId>virtual wire tenant</tenantId>\n\
                    <controlPlaneMode>UNICAST_MODE</controlPlaneMode>\n\
                    <guestVlanAllowed>false</guestVlanAllowed>\n\
                </virtualWireCreateSpec>".format(ls_name, ls_desc)

        api_data = self.nsx_post_xml('/api/2.0/vdn/scopes/{}/virtualwires'.format(transport_zone_id),
                                     data)
        return api_data

    def create_quick_logical_switch(self, ls_name):
        transport_zone_id = self.get_transport_zones()['allScopes'][0]['objectId']
        print(nsx.create_logical_switch(ls_name, transport_zone_id))

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
        api_data = self.get_json_api_data('/api/4.0/edges')
        return api_data

    def get_edge(self, name):
        for edge in self.get_edges()['edgePage']['data']:
            if edge['name'] == name:
                return edge['objectId']

    def get_edge_config(self, edge_id):
        api_data = self.get_json_api_data('/api/4.0/edges/{}'.format(edge_id))
        return api_data

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


vc = Vcenter()
nsx = Nsx(vc)

print(nsx.get_nsx_info())
