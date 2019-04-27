import atexit
from configparser import ConfigParser

from pyVim.connect import Disconnect, SmartConnectNoSSL
from pyVmomi import vim


config = ConfigParser()
config.read('config.ini')

config_vc = 'VCENTER'
user = config[config_vc]['USER']
host = config[config_vc]['HOST']
password = config[config_vc]['PASSWORD']


class Vcenter():
    def __init__(self):
        self.ip = config[config_vc]['HOST']
        self.user = config[config_vc]['USER']
        self.password = config[config_vc]['PASSWORD']

        self.service_instance = SmartConnectNoSSL(host=host,
                                                  user=user,
                                                  pwd=password)
        atexit.register(Disconnect, self.service_instance)
        self.content = self.service_instance.RetrieveContent()

    def get_obj(self, vimtype, name):
        obj = None
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, vimtype, True
        )
        for c in container.view:
            if c.name == name:
                obj = c
                break
        return obj

    def get_all_hosts(self):
        all_hosts = []
        dc_view = self.content.viewManager.CreateContainerView(self.content.rootFolder,
                                                               [vim.Datacenter],
                                                               True)
        for datacenter in dc_view.view:
            for cluster in datacenter.hostFolder.childEntity:
                for host in cluster.host:
                    print(cluster._moId)
                    all_hosts.append(host.name)
        return all_hosts

    def list_all_clusters(self):
        all_clusters = []
        dc_view = self.content.viewManager.CreateContainerView(self.content.rootFolder,
                                                               [vim.Datacenter],
                                                               True)
        for datacenter in dc_view.view:
            for cluster in datacenter.hostFolder.childEntity:
                all_clusters.append(cluster)
        return all_clusters

    def list_all_dvs(self):
        all_obj = []
        dc_view = self.content.viewManager.CreateContainerView(self.content.rootFolder,
                                                               [vim.Datacenter],
                                                               True)
        for datacenter in dc_view.view:
            for obj in datacenter.networkFolder.childEntity:
                if 'dvs-' in obj._moId:
                    all_obj.append(obj)
        return all_obj

    def list_all_datastores(self):
        all_obj = []
        dc_view = self.content.viewManager.CreateContainerView(self.content.rootFolder,
                                                               [vim.Datacenter],
                                                               True)
        for datacenter in dc_view.view:
            for obj in datacenter.datastoreFolder.childEntity:
                all_obj.append(obj)
        return all_obj

    def get_network(self, name):
        return self.get_obj([vim.Network], name)

    def get_datacenter(self):
        dc_view = self.content.viewManager.CreateContainerView(self.content.rootFolder,
                                                               [vim.Datacenter],
                                                               True)
        return dc_view.view[0]

    def get_vcenter_uuid(self):
        about = self.content.about
        return about.instanceUuid

    def rename_vxlan_dvpg(self):
        # NO LONGER IN USE (consolidated edge/mgmt VSS used instead)
        # Renames the created DVPG to Edge, as to reflect it's use
        dvpg_obj = self.get_obj([vim.dvs.DistributedVirtualPortgroup], 'VXLAN')
        print(dvpg_obj)
        # task = dvpg_obj.Rename('Edge')

    def list_hosts_in_cluster(self, cluster_id):
        hosts = []
        datacenter = self.get_datacenter()
        for entity in datacenter.hostFolder.childEntity:
            if entity._moId == cluster_id:
                for host in entity.host:
                    hosts.append(host)
        return hosts


def main():
    vc = Vcenter()
    print(vc.get_all_hosts())


if __name__ == "__main__":
    main()
