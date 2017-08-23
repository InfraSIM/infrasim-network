# IVN: A tool to setup two-layer vswitches and network namespaces

## Setup environment

Install PIP:

    sudo apt-get install python-pip

Install openvswitch:

    sudo apt-get install openvswitch-switch

Install module dependencies:

    sudo pip install -r requirements.txt

## Usage

### Customize configuration file

The configuration file is named network_configuration.yml.
There are two types of components in ivn:

* switches: Two layers of vswitches in the host. br-ex can be connected to outside network, and br-int is connected to interfaces from network namespaces.

* namespaces: You can configure as many namespaces as you need. Network inside a namespace is isolated from host network. By default, for each interface defined in namespace, we'll create a pair interface named veth{} in host to make it reachable to host.

For details please contact [xiar](https://github.com/xiar).


