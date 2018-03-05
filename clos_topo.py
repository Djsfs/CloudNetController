#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        
        core = []           #list of cores switches
        a = []              #list of aggregation switches
        edge = []           #list of edge switches
        hosts =[]           #list of host

        "Set up Core and Aggregate level, Connection Core - Aggregation level"
        ii=1
        kk=cores+1      #counter of the switches
        for i in range(cores):                      
            c=self.addSwitch('core%s'%(ii)) 
            core.append(c)                      #add in core list
            for k in range(fanout):             #every core has fanout number of agreegation nodes
                aggr=self.addSwitch('a%s'%(kk))
                a.append(aggr)                  
                kk+=1
            ii+=1

        print ("cores: ")
        print(core)

        print ("agrr: ")
        print(a)

        
        for i in core:                         #link the core with the aggregation level
            for k in a:
                self.addLink(k,i)
        
    
        #WRITE YOUR CODE HERE!
        pass

        "Set up Edge level, Connection Aggregation - Edge level "


        for i in a:
            for k in range(fanout):
                edges=self.addSwitch('e%s'%(kk))
                edge.append(edges)
                kk+=1
            ii+=1

        print ("edge: ")
        print(edge)

        
        for i in a:
            for k in edge:
                self.addLink(k,i)
        

        #WRITE YOUR CODE HERE!
        pass
        
        "Set up Host level, Connection Edge - Host level "
        kk=1
        for i in edge:
            for k in range(fanout):
                h=self.addHost('h%s'%(kk))
                hosts.append(h)
                kk+=1

        print ("host: ")
        print(hosts)
        
        p=0
        for i in edge:
            for k in range(fanout):

                self.addLink(hosts[p],i)
                p+=1            
                


        #WRITE YOUR CODE HERE!
        pass
	

def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    #net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')

    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])