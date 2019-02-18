from vcenter import Vcenter, config

nsx_license = config['LICENSING']['NSX']
vsan_license = config['LICENSING']['VSAN']
host_license = config['LICENSING']['ESXI']
vcenter_license = config['LICENSING']['VCENTER']


class VcenterLicense:
    def __init__(self, vcenter):
        self.vcenter = vcenter

    def get_nsx_license(self):
        lic_manager = self.vcenter.content.licenseManager.licenseAssignmentManager

        lic_check = lic_manager.QueryAssignedLicenses("nsx-netsec")
        lic_type = lic_check[0].assignedLicense.name
        lic_key = lic_check[0].assignedLicense.licenseKey

        if lic_type == 'NSX for vShield Endpoint':
            lic_ver = ' Free license - '
        elif lic_type == 'NSX for vSphere - Enterprise':
            lic_ver = ' Enterprise license - '

        return lic_ver + lic_key

    def apply_license(self, entity, license):
        lic_manager = self.vcenter.content.licenseManager.licenseAssignmentManager
        lic_manager.UpdateAssignedLicense(entity, license, None)
        return

    def apply_nsx_lic(self):
        self.apply_license("nsx-netsec", nsx_license)
        return

    def apply_vsan_lic(self):
        cluster = self.vcenter.get_obj([vim.ClusterComputeResource], 'VLAB10-Cluster')
        self.apply_license(cluster._moId, vsan_license)

    def apply_host_lic(self):
        host = self.vcenter.get_obj([vim.HostSystem], 'vlab10-h01.mc.net')
        self.apply_license(host._moId, host_license)

    def apply_vcenter_lic(self):
        vc_uuid = self.vcenter.get_vcenter_uuid()
        self.vcenter.apply_license(vc_uuid, vcenter_license)


if __name__ == '__main__':
    vc = Vcenter()
    vc_lic = VcenterLicense(vc)

    print('NSX license currently installed:')
    print(vc_lic.get_nsx_license())
    # vc_lic.apply_vcenter_lic()
