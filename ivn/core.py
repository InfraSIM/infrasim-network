import os
import shutil
import json
import re
import subprocess
import yaml
from pyroute2 import netlink
from pyroute2 import IPDB
from pyroute2 import netns
from pyroute2.iproute import IPRoute


IP_ROUTE = IPRoute()
MAIN_IPDB = IPDB()


def start_process(args):
    """
    Shell command agent
    """
    try:
        p = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        return (p.returncode, out, err)
    except OSError:
        return (-1, None, None)


def exec_cmd_in_namespace(ns, cmd):
    """
    Shell command agent to execute command in namespace
    """
    return start_process(["ip", "netns", "exec", ns] + cmd)

class Topology(object):
    """
    InfraSIM virtual network abstraction, with definition on:
    - namespace
    - openvswitches
    - connection from namespace interface to openvswitch port
    """
    def __init__(self, config_path):
        self.__topo = None
        self.__openvswitch = {}
        self.__namespace = {}
        self.__connection = {}

        with open(config_path, "r") as fp:
            self.__topo = yaml.load(fp)

    def __load(self):
        """
        Resolve topology to data structure
        """
        # load openvswitch
        for ovs_name in self.__topo["ovs"]:
            ovs_info = self.__topo[ovs_name]
            ovs_info["ifname"] = ovs_name
            self.__openvswitch[ovs_name] = InfrasimvSwitch(ovs_info)

        # load namespaces
        for ns_name in self.__topo["namespace"]:
            ns_info = self.__topo[ns_name]
            ns_info["name"] = ns_name
            self.__namespace[ns_name] = InfrasimNamespace(ns_info)

        # load connections
        self.__connection = self.__topo["connection"]

    def create(self):
        """
        Main function to build all infrasim virtual network referring to
        resolved topology
        """
        self.__load()

        for _, ovs in self.__openvswitch.items():
            ovs.add_vswitch()
            ovs.add_all_ports()
            # FIXME: substitute for below code
            # self.__vswitch_ex.set_interface("phy-br-ex", "int-br-ex")
            # self.__vswitch_int.set_interface("int-br-ex", "phy-br-ex")
            ovs.add_interface_d()

        for _, ns in self.__namespace.items():
            ns.create_namespace()
            ns.create_all_interfaces(ref=self.__connection)

        for _, ovs_port in self.__connection.items():
            idx = IP_ROUTE.link_lookup(ifname=ovs_port)[0]
            IP_ROUTE.link("set", index=idx, state="up")

        for _, ns in self.__namespace.items():
            ns.create_interface_d()
            ns.link_up_all()

    def delete(self):
        """
        Main function to clear all infrasim virtual network referring to
        resolved topology
        """
        self.__load()

        for _, ovs in self.__openvswitch.items():
            ovs.del_vswitch()

        for _, ns in self.__namespace.items():
            ns.del_namespace()
            ns.del_interface_d()

    def set_config(self, config_path):
        with open(config_path, "r") as fp:
            self.__topo = yaml.load(fp)

    def get_topo(self):
        return self.__topo

    def __str__(self):
        return json.dumps(self.__topo, indent=4)

class InfrasimNamespace(object):
    """
    Namespace abstraction
    Mainly use ip command set for management
    """
    def __init__(self, ns_info):
        self.__ns_info = ns_info
        self.name = ns_info['name']
        self.ip = IPRoute()
        self.__interfaces = {}
        self.__bridges = {}

    @staticmethod
    def get_namespaces_list():
        return netns.listnetns()

    def create_namespace(self):
        if self.name in self.get_namespaces_list():
            print "name space {} exists.".format(self.name)
            return
        netns.create(self.name)

    def create_all_interfaces(self, ref):
        for intf in self.__ns_info["interfaces"]:
            ifname = intf["ifname"]
            self.__interfaces[ifname] = Interface(intf)
            self.__interfaces[ifname].set_peer(ref.get(ifname, None))
            self.__interfaces[ifname].set_namespace(self.name)
            self.__interfaces[ifname].create_interface()
        for br in self.__ns_info["bridges"]:
            brname = br["ifname"]
            self.__bridges[brname] = Interface(br)
            self.__bridges[brname].set_namespace(self.name)
            self.__bridges[brname].create_bridge()

    def create_interface_d(self):
        netns_path = "/etc/netns"
        ns_network_dir = os.path.join(netns_path, self.name, "network")

        if_down_dir = os.path.join(ns_network_dir, "if-down.d")
        if not os.path.exists(if_down_dir):
            os.makedirs(if_down_dir)

        if_post_down_dir = os.path.join(ns_network_dir, "if-post-down.d")
        if not os.path.exists(if_post_down_dir):
            os.makedirs(if_post_down_dir)

        if_pre_up_dir = os.path.join(ns_network_dir, "if-pre-up.d")
        if not os.path.exists(if_pre_up_dir):
            os.makedirs(if_pre_up_dir)

        if_up_dir = os.path.join(ns_network_dir, "if-up.d")
        if not os.path.exists(if_up_dir):
            os.makedirs(if_up_dir)

        content = ""
        content += "auto lo\n"
        content += "iface lo inet loopback\n"
        content += "\n"

        for _, iobj in self.__interfaces.items():
            content += iobj.compose()

        for _, bobj in self.__bridges.items():
            content += bobj.compose()

        with open(os.path.join(ns_network_dir, "interfaces"), "w") as f:
            f.write(content)

    def del_namespace(self):
        if self.name in netns.listnetns():
            netns.remove(self.name)

    def del_interface_d(self):
        netns_path = "/etc/netns"
        ns_dir = os.path.join(netns_path, self.name)
        try:
            shutil.rmtree(ns_dir)
        except OSError:
            pass

    def link_up_all(self):
        # setup lo
        # self.exec_cmd_in_namespace(["ifdown", "lo"])
        # self.exec_cmd_in_namespace(["ifup", "lo"])
        exec_cmd_in_namespace(self.name, ["ip", "link", "set", "dev", "lo", "up"])

        for _, bobj in self.__bridges.items():
            bobj.down()

        for _, iobj in self.__interfaces.items():
            iobj.down()
            iobj.up()

        for _, bobj in self.__bridges.items():
            bobj.up()


class InfrasimvSwitch(object):
    """
    Openvswitch abstraction
    Mainly use ovs-vsctl command set for management
    """

    def __init__(self, vswitch_info):
        self.__vswitch_info = vswitch_info
        self.name = vswitch_info["ifname"]
        self.oif = None

    @staticmethod
    def get_vswitchs_list():
        return start_process(["ovs-vsctl", "show"])[1]

    def check_vswitch_exists(self):
        ret = start_process(["ovs-vsctl", "br-exists", self.name])[0]
        return ret == 0

    def add_vswitch(self):
        if self.check_vswitch_exists():
            print "vswitch {} already exists so not add it.".format(self.name)
            return

        if start_process(["ovs-vsctl", "add-br", self.name])[0] != 0:
            raise Exception("fail to create vswitch {}.".format(self.name))
        print "vswitch {} is created.".format(self.name)

    def del_vswitch(self):
        if not self.check_vswitch_exists():
            print "vswitch {} doesn't exist so not delete it".format(self.name)
        else:
            if start_process(["ovs-vsctl", "del-br", self.name])[0]:
                raise Exception("fail to delete vswitch {}".format(self.name))
            try:
                os.remove("/etc/network/interfaces.d/{}".format(self.name))
            except OSError:
                pass
            print "vswitch {} is destroyed.".format(self.name)

    def add_port(self, ifname):
        if not self.check_vswitch_exists():
            raise Exception("vswitch {} doesn't exist, please add it first.".format(self.name))

        ret, _, outerr = start_process(["ovs-vsctl", "add-port", self.name, ifname])
        if ret != 0:
            print outerr

    def add_all_ports(self):
        for port in self.__vswitch_info["ports"]:
            self.add_port(port)

    def del_port(self, ifname):
        ret, _, outerr = start_process(["ovs-vsctl", "del-port", self.name, ifname])
        if ret != 0:
            print outerr

    def del_all_ports(self):
        for port in self.__vswitch_info["ports"]:
            self.del_port(port)

    def set_interface(self, ifname, peername):
        self.add_port(ifname)
        ret, _, _ = start_process(["ovs-vsctl",
                                   "set", "interface", ifname,
                                   "type=patch",
                                   "options:peer={}".format(peername)])
        if ret != 0:
            raise Exception("fail to set interface {} for vswitch {}.".format(ifname, self.name))

    def add_interface_d(self):
        content = ""
        if self.__vswitch_info["type"] == "static":
            content += "auto {}\n".format(self.name)
            content += "iface {} inet static\n".format(self.name)
            for key, val in self.__vswitch_info.items():
                if key == "ifname" or key == "type" or key == "ports":
                    continue
                elif val:
                    content += "\t{} {}\n".format(key, val)
        elif self.__vswitch_info["type"] == "dhcp":
            content += "auto {}\n".format(self.name)
            content += "iface {} inet dhcp\n".format(self.name)
        else:
            raise Exception("Unsupported method {}.".format(self.__vswitch_info["type"]))

        with open("/etc/network/interfaces.d/{}".format(self.name), "w") as f:
            f.write(content)

        start_process(["ifdown", self.name])
        returncode, _, err = start_process(["ifup", self.name])
        if returncode != 0:
            raise Exception("Failed to if up {}\nError: {}".format(self.name, err))


class Interface(object):
    """
    Ethernet interface abstraction, including normal interface and bridge
    Mainly use ip command set for management
    """
    def __init__(self, interface_info):
        self.__intf_info = interface_info
        self.__peer = None
        self.__namespace = None

    def create_interface(self):
        ifname = self.__intf_info["ifname"]
        if len(IP_ROUTE.link_lookup(ifname=ifname)) > 0:
            print "ip link {} exists so not create it.".format(ifname)
            return

        if self.__peer:
            if len(IP_ROUTE.link_lookup(ifname=self.__peer)) > 0:
                print "ip link {} exists so not create it.".format(ifname)
                return
        else:
            ps_intf = r"^\d+: (?P<intf>[\w-]+): "
            p_intf = re.compile(ps_intf, re.MULTILINE)
            _, out, _ = exec_cmd_in_namespace(self.__namespace, ["ip", "link"])
            m_intf = p_intf.findall(out)
            if ifname in m_intf:
                print "ip link {} exists in namespace {} so not create it.".\
                        format(ifname, self.__namespace)
                return


        MAIN_IPDB.create(ifname=ifname,
                         kind="veth" if self.__peer else "dummy",
                         peer=self.__peer).commit()
        with MAIN_IPDB.interfaces[ifname] as veth:
            try:
                veth.net_ns_fd = self.__namespace
            except netlink.exceptions.NetlinkError, e:
                if e.code == 17:  # "File exists"
                    pass
                else:
                    raise e

    def create_bridge(self):
        br_name = self.__intf_info["ifname"]
        intf = self.__intf_info.get("bridge_ports", "")

        exec_cmd_in_namespace(self.__namespace, ["brctl", "addbr", "{}".format(br_name)])
        exec_cmd_in_namespace(self.__namespace, ["brctl", "setfd", "{}".format(br_name), "0"])
        exec_cmd_in_namespace(self.__namespace, ["brctl", "sethello", "{}".format(br_name), "1"])
        exec_cmd_in_namespace(self.__namespace, ["brctl", "stp", "{}".format(br_name), "no"])
        if intf:
            exec_cmd_in_namespace(self.__namespace, ["brctl", "addif", "{}".format(br_name), intf])
            exec_cmd_in_namespace(self.__namespace, ["ifconfig", intf, "promisc"])

    def down(self):
        exec_cmd_in_namespace(self.__namespace, ["ifdown", self.__intf_info["ifname"]])

    def up(self):
        exec_cmd_in_namespace(self.__namespace, ["ifup", self.__intf_info["ifname"]])

    def handle_dhcp_type(self):
        content = ""
        content += "auto {}\n".format(self.__intf_info["ifname"])
        content += "iface {} inet dhcp\n".format(self.__intf_info["ifname"])
        content += "\n"
        return content

    def handle_static_type(self):
        content = ""
        content += "auto {}\n".format(self.__intf_info["ifname"])
        content += "iface {} inet static\n".format(self.__intf_info["ifname"])
        content += self.handle_body()
        content += "\n"
        return content

    def handle_body(self):
        content = ""
        sub_content = ""
        for key, val in self.__intf_info.items():
            if key == "ifname" or key == "type" or val is None:
                continue

            if key == "pair":
                continue

            elif key == "bridge":
                sub_content = ""
                old_intf_info = self.__intf_info
                self.__intf_info = self.__intf_info['bridge']
                sub_content = self.compose()
                self.__intf_info = old_intf_info
            else:
                content += "\t{} {}\n".format(key, val)

        content += "\n"
        content += sub_content
        return content

    def compose(self):
        if self.__intf_info["type"] == "dhcp":
            return self.handle_dhcp_type()
        elif self.__intf_info["type"] == "static":
            return self.handle_static_type()
        else:
            raise Exception("Unsupported method {}.".format(self.__intf_info["type"]))

    def set_peer(self, peer):
        self.__peer = peer

    def set_namespace(self, ns):
        self.__namespace = ns
