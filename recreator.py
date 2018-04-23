#!/usr/bin/env python

from ivn.core import Topology
import sys

if __name__ == "__main__":
    if sys.argv[1] == "create":
        topo = Topology("./config.yml")
        topo.create()
    elif sys.argv[1] == "delete":
        topo = Topology("./config.yml")
        topo.delete()
    else:
        print sys.argv[1]
