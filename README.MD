# NALD: NSX Automated Lab Deployment

## Description

NALD follows on from William Lam's PowerCLI vSphere vGhetto Lab Deployment to configure various NSX components. In full deployment it provides end-to-end connectivity from VMs connected to logical switches, through a DLR and ESG into the physical network via OSPF.

This uses pyVmomi to interact with vCenter and the native REST API to interact with the NSX Manager. 

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

When deployed with the default config.ini to a 'vGhetto Lab Deployment' the NALD will build the following topology:
![Design](/design.png?raw=true)

## Configuration

TBC