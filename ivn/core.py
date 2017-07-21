import subprocess
import yaml
import os
import shutil
import netifaces
import json
from pyroute2 import IPDB
from pyroute2 import netns
from pyroute2.iproute import IPRoute


ip_route = IPRoute()
main_ipdb = IPDB()


def start_process(args):
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
    start_process(["ip", "netns", "exec", ns] + cmd)

class Topology(object):
    def __init__(self, config_path):
        self.__topo = None
        self.__openvswitch = {}
        self.__namespace = {}
        self.__connection = {}

        with open(config_path, "r") as fp:
            self.__topo = yaml.load(fp)

    def __load(self):
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
            ns.create_interface_d()

    def delete(self):
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
    def __init__(self, ns_info):
        self.__ns_info = ns_info
        self.name = ns_info['name']
        self.ip = IPRoute()
        # self.ipdb = IPDB(nl=NetNS(self.name))
        self.main_ipdb = IPDB()
        # self.__vswitch = vswitch_instance
        self.__interfaces = {}
        self.__bridges = {}

    @staticmethod
    def get_namespaces_list():
        return netns.listnetns()

    def build_one_namespace(self):
        self.create_namespace()

        for intf in self.__ns_info["interfaces"]:
            # get name
            ifname = intf["ifname"]
            if intf.get("pair") is False:
                self.create_single_virtual_intf_in_ns(intf)
            else:
                global interface_index
                self.create_ip_link_in_ns(ifname, "veth{}".format(interface_index))
                if 'bridge' in intf:
                    self.create_bridge(intf=ifname, br_name=intf['bridge']['ifname'])
                self.__vswitch.add_port("veth{}".format(interface_index))
                idx = self.ip.link_lookup(ifname="veth{}".format(interface_index))[0]
                self.ip.link("set", index=idx, state="up")
                interface_index += 1

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
        shutil.rmtree(ns_dir)

    def create_single_virtual_intf_in_ns(self, intf):
        ifname = intf['ifname']
        if len(self.ip.link_lookup(ifname=ifname)) > 0:
            print "ip link {} exists so not create it.".format(ifname)
            return

        self.main_ipdb.create(ifname=ifname, kind="dummy").commit()
        with self.main_ipdb.interfaces[ifname] as veth:
            veth.net_ns_fd = self.name

        if 'bridge' in intf:
            self.create_bridge(intf=ifname, br_name=intf['bridge']['ifname'])

    def create_ip_link_in_ns(self, ifname, peername):
        if len(self.ip.link_lookup(ifname=ifname)) > 0:
            print "ip link {} exists so not create it.".format(ifname)
            return

        if len(self.ip.link_lookup(ifname=peername)) > 0:
            print "ip link {} exists so not create it.".format(peername)
            return

        # create link peer
        self.main_ipdb.create(ifname=ifname, kind="veth", peer=peername).commit()
        with self.main_ipdb.interfaces[ifname] as veth:
            veth.net_ns_fd = self.name

    def exec_cmd_in_namespace(self, cmd):
        start_process(["ip", "netns", "exec", self.name] + cmd)

    def link_up_all(self):
        # setup lo
        # self.exec_cmd_in_namespace(["ifdown", "lo"])
        # self.exec_cmd_in_namespace(["ifup", "lo"])
        self.exec_cmd_in_namespace(["ip", "link", "set", "dev", "lo", "up"])

        for intf_info in self.__ns_info["interfaces"]:
            if "bridge" in intf_info:
                self.exec_cmd_in_namespace(["ip", "link", "set", "dev", intf_info["ifname"], "up"])
                self.exec_cmd_in_namespace(["ifdown", intf_info["bridge"]["ifname"]])
                self.exec_cmd_in_namespace(["ifup", intf_info["bridge"]["ifname"]])
            else:
                self.exec_cmd_in_namespace(["ifdown", intf_info["ifname"]])
                self.exec_cmd_in_namespace(["ifup", intf_info["ifname"]])

    def create_bridge(self, intf="einf0", br_name="br0"):
        self.exec_cmd_in_namespace(["brctl", "addbr", "{}".format(br_name)])
        self.exec_cmd_in_namespace(["brctl", "addif", "{}".format(br_name), intf])
        self.exec_cmd_in_namespace(["brctl", "setfd", "{}".format(br_name), "0"])
        self.exec_cmd_in_namespace(["brctl", "sethello", "{}".format(br_name), "1"])
        self.exec_cmd_in_namespace(["brctl", "stp", "{}".format(br_name), "no"])
        self.exec_cmd_in_namespace(["ifconfig", intf, "promisc"])

    def build_ns_configuration(self):
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

        intf_list = []
        for intf_info in self.__ns_info["interfaces"]:
            intf_obj = Interface(intf_info)
            intf_list.append(intf_obj)

        for iobj in intf_list:
            content += iobj.compose()

        with open(os.path.join(ns_network_dir, "interfaces"), "w") as f:
            f.write(content)


class InfrasimvSwitch(object):
    def __init__(self, vswitch_info):
        self.__vswitch_info = vswitch_info
        self.name = vswitch_info["ifname"]
        self.oif = None

    @staticmethod
    def get_vswitchs_list():
        return start_process(["ovs-vsctl", "show"])[1]

    def build_one_vswitch(self):
        # add port in configuration to vswitch
        if "ports" in self.__vswitch_info:
            for port in self.__vswitch_info["ports"]:
                self.add_port(port["ifname"])

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
        returncode, out, err = start_process(["ifup", self.name])
        if returncode != 0:
            raise Exception("Failed to if up {}\nError: ".format(self.name, err))

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

        ret, output, outerr = start_process(["ovs-vsctl", "add-port", self.name, ifname])
        if ret != 0:
            print outerr

    def add_all_ports(self):
        for port in self.__vswitch_info["ports"]:
            self.add_port(port)

    def del_port(self, ifname):
        ret, output, outerr = start_process(["ovs-vsctl", "del-port", self.name, ifname])
        if ret != 0:
            print outerr

    def del_all_ports(self):
        for port in self.__vswitch_info["ports"]:
            self.del_port(port)

    def set_interface(self, ifname, peername):
        self.add_port(ifname)
        ret, output, outerr = start_process(["ovs-vsctl", "set", "interface", ifname, "type=patch", "options:peer={}".format(peername)])
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
        returncode, out, err = start_process(["ifup", self.name])
        if returncode != 0:
            raise Exception("Failed to if up {}\nError: ".format(self.name, err))


class Interface(object):
    def __init__(self, interface_info):
        self.__intf_info = interface_info
        self.__peer = None
        self.__namespace = None

    def create_interface(self):
        global ip_route
        global main_ipdb

        ifname = self.__intf_info["ifname"]
        if len(ip_route.link_lookup(ifname=ifname)) > 0:
            print "ip link {} exists so not create it.".format(ifname)
            return

        if self.__peer:
            if len(ip_route.link_lookup(ifname=self.__peer)) > 0:
                print "ip link {} exists so not create it.".format(ifname)
                return

        main_ipdb.create(ifname=ifname,
                         kind="veth" if self.__peer else "dummy",
                         peer=self.__peer).commit()
        with main_ipdb.interfaces[ifname] as veth:
            veth.net_ns_fd = self.__namespace

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
