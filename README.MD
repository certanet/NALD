# NALD: NSX Automated Lab Deployment

## Description

NALD follows on from William Lam's PowerCLI VVLD [(vSphere vGhetto Lab Deployment)](https://github.com/lamw/vghetto-vsphere-automated-lab-deployment) to configure various NSX (Data Center for vSphere) components. In full deployment it provides end-to-end connectivity from VMs connected to logical switches, through a DLR and ESG into the physical network via OSPF.

This uses pyVmomi to interact with vCenter and the native REST API to interact with the NSX Manager and has been tested on the following versions (others should work but YMMV):
- **Python**: 3.5, 3.6
- **vSphere**: 6.7, 6.7U1, 6.7U2
- **NSX**: 6.4.4, 6.4.5


## Tasks Performed

* Apply NSX license
* Host-Prep on cluster (install NSX VIBs and VXLAN)
* Create Transport Zone and Segment ID Pool
* Create IP Pools (Controller and VTEP)
* Deploy controller(s)
* Create Logical Switches
* Deploy DLR
* Deploy ESG
* Configure OSPF between DLR & ESG and ESG and physical network

## Design

When deployed with the default config.ini to a VVLD, NALD will build the following topology:
![Design](/design.png?raw=true)

## Usage
NALD assumes that the undelying vSphere infrastructure is deployed in a similar topology to VVLD and that the physical network has been configured for OSPF area 0 connecting to the ESG that will be deployed.

### Windows
1. Install Python and download NALD using `git clone https://github.com/certanet/NALD.git` or as a .zip and extract
2. Create a virtual env to separate NALD from system packages:
`python -m venv venv`
3. Enter the virtual env:
`venv\Scripts\activate.bat`
4. Install the packages required to run NALD:
`pip install -r requirements.txt`
5. Rename the provided `config.ini.example` file to `config.ini`
6. Replace the configuration settings to match your environment, note that the defaults have been set to work with a VVLD, but **at a minimum you must enter an NSX license**, as this is required for host prep.
7. Run NALD against your vSphere and NSX environment:
`python nsxm.py`
8. Watch your automated lab deploy before your very eyes!

## To Do

- ~~Convert remaining methods (DLR and ESG) to JSON~~
- ~~Remove seperate method for edge routing~~
- Add SSL VPN config to ESG
