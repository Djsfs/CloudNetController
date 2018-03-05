#generic imports
import sys
import os
import random
import time
import traceback
import csv

#pox-specific imports
from pox.core import core
from pox.openflow import ethernet
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.revent import *
from pox.lib.recoco import Timer

#ryu imports
#from ryu.topology import event, switches
#from ryu.topology.api import get_switch, get_link

#networkx import for graph management
import networkx as nx

#for beautiful prints of dicts, lists, etc,
from pprint import pprint as pp

log = core.getLogger()

MAX_PHYS_PORTS = 0xFF00


class CloudNetController (EventMixin):

	_neededComponents = set(['openflow_discovery'])

	def __init__(self, firewall_capability, migration_capability, firewall_policy_file, migration_events_file):
		super(EventMixin, self).__init__()

		G=nx.Graph()


		#generic controller information
		self.switches = {}     													# key=dpid, value = SwitchWithPaths instance
		self.sw_sw_ports = {}  													# key = (dpid1,dpid2), value = outport of dpid1
		self.adjs = {}         													# key = dpid, value = list of neighbors
		self.arpmap = {} 														# key=host IP, value = (mac,dpid,port)
		self._paths_computed = False 											#boolean to indicate if all paths are computed (converged routing)
		self.ignored_IPs = [IPAddr("0.0.0.0"), IPAddr("255.255.255.255")] 		#these are used by openflow discovery module

		#invoke event listeners
		if not core.listen_to_dependencies(self, self._neededComponents):
			self.listenTo(core)
		self.listenTo(core.openflow)

		#module-specific information
		self.firewall_capability = firewall_capability
		self.migration_capability = migration_capability
		self.firewall_policies = None
		self.migration_events = None
		self.migrated_IPs = None
		if self.firewall_capability:
			self.firewall_policies = self.read_firewall_policies(firewall_policy_file)
		if self.migration_capability:
			self.migration_events = self.read_migration_events(migration_events_file)
			self.old_migrated_IPs = {} 										#key=old_IP, value=new_IP
			self.new_migrated_IPs = {} 										#key=new_IP, value=old_IP
			for event in self.migration_events:
				migration_time = event[0]
				old_IP = event[1]
				new_IP = event[2]
				Timer(migration_time, self.handle_migration, args = [IPAddr(old_IP), IPAddr(new_IP)])

	def read_firewall_policies(self, firewall_policy_file):
		firewall_policies = {}
		with open(firewall_policy_file, 'r') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				tenant_id = row[0]
				for ip in row[1:len(row)]:
					firewall_policies[IPAddr(ip)] = int(tenant_id)
					print ("TENANTTTTTTTTTTTTTTTTTTTTTTTTTTT: ",firewall_policies[IPAddr(ip)])
		return firewall_policies

	def read_migration_events(self, migration_info_file):
		migration_events = []
		with open(migration_info_file, 'r') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				migration_time = int(row[0])
				old_ip = IPAddr(row[1])
				new_ip = IPAddr(row[2])
				migration_events.append((migration_time, old_ip, new_ip))
		return migration_events

	def _handle_ConnectionUp(self, event):
		if event.dpid not in self.switches:
			self.switches[event.dpid] = SwitchWithPaths()
			if event.dpid not in self.adjs:
				self.adjs[event.dpid] = set([])
		self.switches[event.dpid].connect(event.connection)
		#send unknown ARP and IP packets to controller (install rules for that with low priority)
		msg_ARP = of.ofp_flow_mod()
		msg_IP  = of.ofp_flow_mod()
		msg_ARP.match.dl_type = 0x0806
		msg_IP.match.dl_type  = 0x0800
		msg_ARP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		msg_IP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		msg_ARP.priority = of.OFP_DEFAULT_PRIORITY - 1
		msg_IP.priority  = of.OFP_DEFAULT_PRIORITY - 1
		event.connection.send(msg_ARP)
		event.connection.send(msg_IP)

	def _handle_ConnectionDown(self, event):
		ips_to_forget = []
		for ip in self.arpmap:
			(mac, dpid, port) = self.arpmap[ip]
			if dpid == event.dpid:
				ips_to_forget.append(ip)
		for ip in ips_to_forget:
			del self.arpmap[ip]
		if (event.dpid in self.switches):
			self.switches[event.dpid].disconnect()
			del self.switches[event.dpid]
		#let the discovery module deal with the port removals...

	def flood_on_all_switch_edges(self, packet, this_dpid, this_port):
		for src_dpid in self.switches:
			no_flood_ports = set([]) #list of non-flood ports
			if src_dpid in self.adjs:
				for nei_dpid in self.adjs[src_dpid]:
					no_flood_ports.add(self.sw_sw_ports[(src_dpid,nei_dpid)])
			if src_dpid == this_dpid:
				no_flood_ports.add(this_port)
			self.switches[src_dpid].flood_on_switch_edge(packet, no_flood_ports)

	def update_learned_arp_info(self, packet, dpid, port):
		src_ip = None
		src_mac = None
		if packet.type == packet.ARP_TYPE:
			src_mac = EthAddr(packet.src)
			src_ip  = IPAddr(packet.next.protosrc)
		elif packet.type == packet.IP_TYPE:
			src_mac = EthAddr(packet.src)
			src_ip  = IPAddr(packet.next.srcip)
		else:
			pass
		if (src_ip != None) and (src_mac != None):
			self.arpmap[src_ip] = (src_mac, dpid, port)

	def _handle_PacketIn(self, event):
		packet = event.parsed
		dpid = event.dpid
		inport = event.port

		def handle_ARP_pktin():
			srcip = IPAddr(packet.next.protosrc)
			print "__________________________________srcip: ",srcip
			dstip = IPAddr(packet.next.protodst)
			print "__________________________________dstip: ",dstip
			if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
				return

			if packet.next.opcode == arp.REQUEST:
				log.info("Handling ARP packet: %s requests the MAC of %s" % (str(srcip), str(dstip)))
				self.update_learned_arp_info(packet, dpid, inport)

				#FIREWALL functionality
				if self.firewall_capability:
					try:
						
						src=0																#temporary src switch counter  
						dst=0																#temporary dst switch counter
						for key, value in self.firewall_policies.items():					#here we check if src and dst switches are both in the same tan
							if key == srcip:
								src=value
							if key ==dstip:
								dst = value
																						#handle ARP and IP Packetsins and install rules on the  OpenFlow  switches
																						#to  drop  packets  whenever  tenants  from  different  services  attempt  to communicate.
																						#so given a topology with 2 tenants we check if src switch and dst are in from defferent services
																						#so we drop those packets.
						if src != dst:														
								self.drop_packets(dstip, packet)

						pass
					except KeyError:
						log.info("IPs not covered by policy!")
						return

				if self.migration_capability:
					#ignore ARP requests coming from old migrated IPs or directed to new ones
					if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
						return

				if dstip in self.arpmap:
					log.info("I know where to send the crafted ARP reply!")
					(req_mac, req_dpid, req_port) = self.arpmap[dstip]
					(dst_mac, dst_dpid, dst_port) = self.arpmap[srcip]
					self.switches[dst_dpid].send_arp_reply(packet, dst_port, req_mac)
				else:
					log.info("Flooding initial ARP request on all switch edges")
					self.flood_on_all_switch_edges(packet, dpid, inport)

			elif packet.next.opcode == arp.REPLY:
				log.info("Handling ARP packet: %s responds to %s" % (str(srcip), str(dstip)))
				self.update_learned_arp_info(packet, dpid, inport)

				#FIREWALL functionality
				if self.firewall_capability:
					try:
						
						src=0																#temporary src switch counter  
						dst=0																#temporary dst switch counter
						for key, value in self.firewall_policies.items():					#here we check if src and dst switches are both in the same tan
							if key == srcip:
								src=value
							if key ==dstip:
								dst = value
																						#handle ARP and IP Packetsins and install rules on the  OpenFlow  switches
																						#to  drop  packets  whenever  tenants  from  different  services  attempt  to communicate.
																						#so given a topology with 2 tenants we check if src switch and dst are in from defferent services
																						#so we drop those packets.
						if src != dst:														
								self.drop_packets(dstip, packet)


						pass
					except KeyError:
						return

				if self.migration_capability:
					#ignore ARP replies coming from old migrated IPs or directed to new ones
					if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
						return

				if dstip in self.arpmap.keys():
					log.info("I know where to send the initial ARP reply!")
					(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
					self.switches[dst_dpid].send_packet(dst_port, packet)
				else:
					log.info("Flooding initial ARP reply on all switch edges")
					self.flood_on_all_switch_edges(packet,dpid,inport)
			else:
				log.info("Unknown ARP type")
				return

		def handle_IP_pktin():
			srcip = IPAddr(packet.next.srcip)
			dstip = IPAddr(packet.next.dstip)
			if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
				return

			log.info("Handling IP packet between %s and %s" % (str(srcip), str(dstip)))

			#FIREWALL functionality
			if self.firewall_capability:
				try:                                                                                                                   
					#WRITE YOUR CODE HERE!
						
					src=0																#temporary src switch counter  
					dst=0																#temporary dst switch counter
					for key, value in self.firewall_policies.items():					#here we check if src and dst switches are both in the same tan
						if key == srcip:
							src=value
						if key ==dstip:
							dst = value
																						#handle ARP and IP Packetsins and install rules on the  OpenFlow  switches
																						#to  drop  packets  whenever  tenants  from  different  services  attempt  to communicate.
																						#so given a topology with 2 tenants we check if src switch and dst are in from defferent services
																						#so we drop those packets.
					if src != dst:														
							self.drop_packets(dstip, packet)

					pass
				except KeyError:
					log.info("IPs not covered by policy!")
					return

			if self._paths_computed:
				#print "Routing calculations have converged"
				log.info("Path requested for flow %s-->%s" % (str(srcip), str(dstip)))

				if dstip in self.arpmap: #I know where to send the packet
					(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]

					#MIGRATION functionality
					if self.migration_capability:
						#IP packet goes to old server after migration is done
						if dstip in self.old_migrated_IPs:
							(dst_mac, dst_dpid, dst_port) = self.arpmap[self.old_migrated_IPs[dstip]]
							#install path to new server and change packet headers
							log.info("Installing migrated forward path towards: old IP: %s, new IP: %s" % (str(dstip), str(self.old_migrated_IPs[dstip])))
							self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=True)
							log.info("Forward migrated path installed")

						#IP packet comes from new server after migration is done
						elif srcip in self.new_migrated_IPs:
							(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
							log.info("Installing migrated reverse path from: old IP: %s, new IP: %s" % (str(srcip), str(self.new_migrated_IPs[srcip])))
							self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=False)
							log.info("Reverse migrated path installed")
						else:
							self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
					else:
						self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
				else:
					self.flood_on_all_switch_edges(packet, dpid, inport)
			else:
				print "Routing calculations have not converged, discarding packet"
				return

		#--------------------------------------------------------------------------------------------------------------
		if packet.type == packet.LLDP_TYPE:
			return

		elif packet.type == packet.ARP_TYPE:
			handle_ARP_pktin()
			return

		elif packet.type == packet.IP_TYPE:
			handle_IP_pktin()
			return

		else:
			#log.info("Unknown Packet type: %s" % packet.type)
			return


	def install_end_to_end_IP_path(self, event, dst_dpid, final_port, packet):

		path_list = random.choice(self.switches[event.dpid]._paths[dst_dpid])												#we randomly select a shortest path from the switch 
																															#until the destination switch
																															
		reverse_list = path_list[::-1] 																						#reverse the path_list so 1st elemnt of the list is the
																															# dst switch

		#here we trigger the event when a host wants to send packet to a host on the same neigbourhood 
		#same neighbourhood means that we have only one switch on the path list so we send the packet throw this switch to the final_port that 
		# has given by default
		if (len(path_list)==1):
			print "Aderfia!"
			#port = final_port
			match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)			#we make the match of source and destination switch
			self.switches[event.dpid].install_output_flow_rule(final_port,match)											#we install the output_flow_rule at the final port from last switch
																															#to destination host
			self.switches[event.dpid].send_packet(final_port,event.data)													#we send the packet using send_packet function
		
		#here we trigger the event when a host wants to send a packet to an another host that is not in the same 
		#neigbourhood and that means that there is a nubmer of switces beetween those 2 hosts to communicate.We
		#install the flow rules in the reverse order from the given path and after this we send the packet thow the first switch
		#port and this packet follows the rules we enstablished before and finally arrives at the end_host
		else:
			print "Ksaderfia!"
			for i in range(len(reverse_list)):
				if (i==0):
					#here we endstablish the rule that the last switch will send the packet to the right host
					
					# last_switch -->(final_port)--> dst_host

					match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)		#we make the match of source and destination switch
					self.switches[reverse_list[i]].install_output_flow_rule(final_port,match)
				else:
					#here we enstablish the rules so the switches can communicate on the right order after this
					#we install the output flow rule on the src switch so it gives the route to the dst_switch that the packet 
					#will travel

					port = self.sw_sw_ports[(reverse_list[i],reverse_list[i-1])]
					match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)		#we make the match of source and destination switch
					self.switches[reverse_list[i]].install_output_flow_rule(port,match)

			#after we have already have establish the rules we can send the packet throw the port of the first switch and the and packet 
			#will follow the rules till its destination
			port = self.sw_sw_ports[(event.dpid,reverse_list[len(reverse_list)-2])]										# we take the port of the first switch of  path_list
			self.switches[event.dpid].send_packet(port,event.data)  													# we send the packet using the send_packet function       



		pass

		
	def install_migrated_end_to_end_IP_path(self, event, dst_dpid, dst_port, packet, forward_path=True):

		path_list = random.choice(self.switches[event.dpid]._paths[dst_dpid])											#we randomly select a shortest path from the switch 
		reverse_list=path_list[::-1] #reverse the path list  															#until the destination switch
		


		if (forward_path==True):
			inactive=packet.next.dstip
			new=self.old_migrated_IPs[inactive]
			(new_mac,new_dpid,new_inport) = self.arpmap[new]


			#here we trigger the event when a host wants to send packet to a host on the same neigbourhood 
			#same neighbourhood means that we have only one switch on the path list so we send the packet throw this switch to the final_port that 
			# has given by default
			if(len(path_list)==1):
				print "Aderfia"
				match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
				self.switches[event.dpid].install_forward_migration_rule(new_inport,new_mac,new,match)
				self.switches[event.dpid].send_forward_migrated_packet(new_inport,new_mac,new,event.data)

		#here we trigger the event when a host wants to send a packet to an another host that is not in the same 
		#neigbourhood and that means that there is a nubmer of switces beetween those 2 hosts to communicate.We
		#install the flow rules in the reverse order from the given path and after this we send the packet thow the first switch
		#port and this packet follows the rules we enstablished before and finally arrives at the end_host
			else:
				print"Ksaderfia!"
				for i in range(len(reverse_list)):
					if (i==0):
						match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
						self.switches[reverse_list[i]].install_forward_migration_rule(new_inport,new_mac,new,match)
					else:
						port = self.sw_sw_ports[(reverse_list[i],reverse_list[i-1])]
						match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
						self.switches[reverse_list[i]].install_output_flow_rule(port,match)
				port = self.sw_sw_ports[(event.dpid,reverse_list[len(reverse_list)-2])]
				self.switches[event.dpid].send_forward_migrated_packet(port,new_mac,new,event.data)  



		else:
			fake=packet.next.dstip
			old=self.new_migrated_IPs[fake]
			(new_mac, new_dpid, new_inport)=self.arpmap[old]

			#here we trigger the event when a host wants to send packet to a host on the same neigbourhood 
			#same neighbourhood means that we have only one switch on the path list so we send the packet throw this switch to the final_port that 
			# has given by default
			
			if (len(path_list)==1):
				print "Aderfia!"
				match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
				self.switches[event.dpid].install_reverse_migration_rule(new_inport,new_mac,old,match)
				self.switches[event.dpid].send_reverse_migrated_packet(new_inport,new_mac,old,event.data)


		#here we trigger the event when a host wants to send a packet to an another host that is not in the same 
		#neigbourhood and that means that there is a nubmer of switces beetween those 2 hosts to communicate.We
		#install the flow rules in the reverse order from the given path and after this we send the packet thow the first switch
		#port and this packet follows the rules we enstablished before and finally arrives at the end_host
			else:
				print "Ksaderfia!"		
				for i in range(len(reverse_list)):
					if (i==0):
						match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
						self.switches[reverse_list[i]].install_reverse_migration_rule(new_inport,new_mac,old,match)
					else:
						port = self.sw_sw_ports[(reverse_list[i],reverse_list[i-1])]
						match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=packet.payload.srcip,nw_dst=packet.payload.dstip)
						self.switches[reverse_list[i]].install_output_flow_rule(port,match)
				port = self.sw_sw_ports[(event.dpid,reverse_list[len(reverse_list)-2])]
				self.switches[event.dpid].send_reverse_migrated_packet(port,new_mac,old,event.data)  

		pass
	

	def handle_migration(self, old_IP, new_IP):
		log.info("Handling migration from %s to %s..." % (str(old_IP), str(new_IP)))
		# create ofp_flow_mod message to delete all flows
		# to the destination to be migrated
		msg_1 = of.ofp_flow_mod()
		match_1 = of.ofp_match()
		match_1.dl_type = 0x0800
		match_1.nw_dst = old_IP
		msg_1.match = match_1
		msg_1.command = of.OFPFC_DELETE
		# create ofp_flow_mod message to delete all flows
		# coming from the source that will host the migrated one
		msg_2 = of.ofp_flow_mod()
		match_2 = of.ofp_match()
		match_2.dl_type = 0x0800
		match_2.nw_src = new_IP
		msg_2.match = match_2
		msg_2.command = of.OFPFC_DELETE
		# send the ofp_flow_mod messages to all switches
		# leading to the destination to be migrated (or coming from the source that will host it)
		for sw in self.switches:
			self.switches[sw].connection.send(msg_1)
			log.info("Rules having as dest %s removed at switch: %i" % (str(old_IP), sw))
			self.switches[sw].connection.send(msg_2)
			log.info("Rules having as source %s removed at switch: %i" % (str(new_IP), sw))
		log.info("Rules deleted, now new IP e2e paths will be automatically migrated to the new IP %s" % (str(new_IP)))
		self.old_migrated_IPs[old_IP] = new_IP
		self.new_migrated_IPs[new_IP] = old_IP
		(new_mac, new_dpid, new_inport) = self.arpmap[self.old_migrated_IPs[old_IP]]
		self.arpmap[old_IP] = (new_mac, new_dpid, new_inport)
		log.info("Arpmap for old ip updated")

	def drop_packets(self, dpid, packet):
		match = of.ofp_match.from_packet(packet)													# we make a match of the packet
		self.switches[dpid].install_drop_flow_rule(match, idle_timeout=0, hard_timeout=0)			# and we drop it for the flow

	def _handle_openflow_discovery_LinkEvent(self, event):
		self._paths_computed = False
		link = event.link
		dpid1 = link.dpid1
		port1 = link.port1
		dpid2 = link.dpid2
		port2 = link.port2
		if dpid1 not in self.adjs:
			self.adjs[dpid1] = set([])
		if dpid2 not in self.adjs:
			self.adjs[dpid2] = set([])

		if event.added:
			self.sw_sw_ports[(dpid1,dpid2)] = port1
			self.sw_sw_ports[(dpid2,dpid1)] = port2
			self.adjs[dpid1].add(dpid2)
			self.adjs[dpid2].add(dpid1)
		else:
			if (dpid1,dpid2) in self.sw_sw_ports:
				del self.sw_sw_ports[(dpid1,dpid2)]
			if (dpid2,dpid1) in self.sw_sw_ports:
				del self.sw_sw_ports[(dpid2,dpid1)]
			if dpid2 in self.adjs[dpid1]:
				self.adjs[dpid1].remove(dpid2)
			if dpid1 in self.adjs[dpid2]:
				self.adjs[dpid2].remove(dpid1)

		print "Current switch-to-switch ports:"
		pp(self.sw_sw_ports)
		print "Current adjacencies:"
		pp(self.adjs)
		self._paths_computed=False
		self.checkPaths()
		if self._paths_computed == False:
			print "Warning: Disjoint topology, Shortest Path Routing converging"
		else:
			print "Topology connected, Shortest paths (re)computed successfully, Routing converged"
			print "--------------------------"
			for dpid in self.switches:
				self.switches[dpid].printPaths()
			print "--------------------------"

	def checkPaths(self):
		if not self._paths_computed:
			self._paths_computed = ShortestPaths(self.switches, self.adjs)
		return self._paths_computed

	def __str__(self):
		return "Cloud Network Controller"


class SwitchWithPaths (EventMixin):
	def __init__(self):
		self.connection = None
		self.dpid = None
		self.ports = None
		self._listeners = None
		self._paths = {}

	def __repr__(self):
		return dpidToStr(self.dpid)

	def appendPaths(self, dst, paths_list):
		if dst not in self._paths:
			self._paths[dst] = []
		self._paths[dst] = paths_list

	def clearPaths(self):
		self._paths = {}

	def printPaths(self):
		for dst in self._paths:
			equal_paths_number = len(self._paths[dst])
			if equal_paths_number > 1:
				print "There are %i shortest paths from switch %i to switch %i:" % (equal_paths_number, self.dpid, dst)
			else:
				print "There is exactly one shortest path from switch %i to switch %i:" % (self.dpid, dst)
			for path_index in range(0, equal_paths_number):
				for u in self._paths[dst][path_index]:
					 print "%i," % (u),
				print ""

	def connect(self, connection):
		if self.dpid is None:
			self.dpid = connection.dpid
		assert(self.dpid == connection.dpid)
		if self.ports is None:
			self.ports = connection.features.ports
		log.info("Connect %s" % (connection))
		self.connection = connection
		self._listeners = self.listenTo(connection)

	def disconnect(self):
		if self.connection is not None:
			log.info("Disconnect %s" % (self.connection))
			self.connection.removeListeners(self._listeners)
			self.connection = None
			self._listeners = None

	def flood_on_switch_edge(self, packet, no_flood_ports):

		for i in self.ports:        
			if (i.port_no != 65534):                                                    #we dont want to flood the port that connect the switch to the controller
				if (i.port_no not in no_flood_ports):
					print("TO PORT:->>> einai : ",i.port_no)
					self.send_packet(i.port_no,packet)                                  # we send the packet throw the send_packet() if the port 
																						# isnt in no_flood_ports witch is the ports that we dont 
																						# need to send packets and we dont want to send to the 65534  
																						# witch is the management port of switch which connects to controller

		pass

	def send_packet(self, outport, packet_data=None):
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

	def send_arp_reply(self, packet, dst_port, req_mac):
		#WRITE YOUR CODE HERE!
		print("_________________ ARP REPLY _______to the port  >____",dst_port)
		#create ARP REPLY
		my_arp = arp()                                                                  # writting the headers on arp() function
		my_arp.hwtype = my_arp.HW_TYPE_ETHERNET
		my_arp.protype = my_arp.PROTO_TYPE_IP
		my_arp.opcode=arp.REPLY
		my_arp.hwsrc = req_mac
		my_arp.hwdst =packet.payload.hwsrc
		my_arp.protosrc = packet.payload.protodst
		my_arp.protodst = packet.payload.protosrc        

		#crete ETHERNET packet
		ether = ethernet()                                                              # writting the headers on ethernet() function
		ether.type = ethernet.ARP_TYPE
		ether.dst=packet.payload.hwsrc
		ether.src=req_mac
		ether.set_payload(my_arp) 

		# Create OF message 
		msg = of.ofp_packet_out()
		msg.data = ether.pack()                                                         # we pack the data of ethernet packet using pack()
		msg.in_port = dst_port
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		self.connection.send(msg)                                                       # we send the of message throw the send()
		

	def install_output_flow_rule(self, outport, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

	def install_drop_flow_rule(self, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		msg.actions = [] #empty action list for dropping packets
		self.connection.send(msg)

	def send_forward_migrated_packet(self, outport, dst_mac, dst_ip, packet_data=None):
		#WRITE YOUR CODE HERE!                                                                                                              
		
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data                                              
		msg.actions.append(of.ofp_action_output(port=outport))
		msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
		self.connection.send(msg)


		pass

	def send_reverse_migrated_packet(self, outport, src_mac, src_ip, packet_data=None):
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data
		msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)        

		pass
		
	def install_forward_migration_rule(self, outport, dst_mac, dst_ip, match, idle_timeout=0, hard_timeout=0):
		#WRITE YOUR CODE HERE!                                                                                                                  
		msg=of.ofp_flow_mod()
		msg.match=match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout=idle_timeout
		msg.hard_timeout=hard_timeout
		msg.actions =[]# empty action list for dropping packets
		msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

		pass

	def install_reverse_migration_rule(self, outport, src_mac, src_ip, match, idle_timeout=0, hard_timeout=0):
		#WRITE YOUR CODE HERE!                                                                                                                  
		#
		
		msg=of.ofp_flow_mod()
		msg.match=match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout=idle_timeout
		msg.hard_timeout=hard_timeout
		msg.actions =[]# empty action list for dropping packets
		msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)
		pass


def ShortestPaths(switches, adjs):
	#print switches
	#print adjs
	G=nx.Graph()                                                                            #we create a new instance of a graph switces witch takes nodes 

	for switch in adjs: 
		G.add_node(switch)                                                                  #add new switch node to the graph using add_node()
		for adj in adjs[switch]:
			G.add_edge(switch,adj)                                                          #add an edge from switch to a specific adj using add_edge(sw1,sw2) where sw2 is the adj of sw1 


	#print(G.nodes())
	#print(G.edges())

	try:
		for dpid in adjs:           
			for adj in switches:            
				switches[dpid].appendPaths(adj,list(nx.all_shortest_paths(G,dpid,adj)))     #adding the sortest path from the graph between 2 switches using all_shortest_paths()

	except nx.NetworkXNoPath:                                                               #Exception that handles the case when the NetworkX package is unable to calculate a path
		print ("Network X no Path ")                                                        #for a given sourse and destination because of a disconnected network/graph

	return True                                                                             # returns boolean
	pass

	
def str_to_bool(str):
	assert(str in ['True', 'False'])
	if str=='True':
		return True
	else:
		return False

		
def launch(firewall_capability='True', migration_capability='True',
		   firewall_policy_file='./ext/firewall_policies.csv', migration_events_file='./ext/migration_events.csv'):
	"""
	Args:
		firewall_capability  : boolean, True/False
		migration_capability : boolean, True/False
		firewall_policy_file : string, filename of the csv file with firewall policies
		migration_info_file  : string, filename of the csv file with migration information
	"""
	log.info("Loading Cloud Network Controller")
	firewall_capability = str_to_bool(firewall_capability)
	log.info("Firewall Capability enabled: %s" % (firewall_capability))
	migration_capability = str_to_bool(migration_capability)
	log.info("Migration Capability enabled: %s" % (migration_capability))
	core.registerNew(CloudNetController, firewall_capability, migration_capability, firewall_policy_file, migration_events_file)
	log.info("Network Controller loaded")