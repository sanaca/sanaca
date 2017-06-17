#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import datetime
import dpkt as pc
import time
import dpkt
import socket
import pyshark
import tempfile
import re
import subprocess
import csv
from datetime import datetime
from r2a import *

os.system('clear')
class colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

def Banner():


	print colors.BLUE + (" "*43+"[-----Forensic Réseau-----]") + colors.END
	print colors.YELLOW   + (" "*55+"[-----Analyseur de pcap-----]") + colors.END


Banner()




print colors.RED+ "+++++++++++++++++++++++++++++++++++++++" + colors.END
print colors.GREEN + ("Tapez   -1- pour L'Analyse d'un pcap") + colors.END
print colors.GREEN + ("Tapez   -2- pour Capturer le RZO en temps réel") + colors.END
print colors.GREEN + ("Tapez   -3- pour Creer un pcap à partir de regles snort") + colors.END
print colors.GREEN + ("Tapez   -4- pour le traitement d'un pcap") + colors.END
print colors.RED + "+++++++++++++++++++++++++++++++++++++++\n" + colors.END


def packet():

		pcap = raw_input("pcap à analyser (chemin complet) > ")
		if pcap == pcap:
			control = (os.popen("file " '%s' %pcap)).read()
			if 'capture file' in control:
				pass
			else:
				print colors.BOLD + ("Verifier le chemin du pcap") + colors.END
				sys.exit()
		while True:

			print "\n"
			print colors.BLUE + (" " * 25 + "|-Que souhaitez-vous investiguer? -|\n") + colors.END
			print colors.GREEN + (" 1-Informations sur le PCAP" + " " * 13 + "2-Recherche de pattern\n") + colors.END
			print colors.GREEN + (" 3-Liste des url's" + " " * 17 + "4-Liste des useragents\n") + colors.END
			print colors.GREEN + (" 5-Requetes DNS" + " " * 17 + "6-Details des connexions\n") + colors.END
			print colors.GREEN + (" 7-liste des ports utilises" + " " * 13 + "8-Liste des ip's\n") + colors.END
			print colors.GREEN + (" 9-Filtre wireshark" + " " * 13 + "10-Sites visites \n") + colors.END
			print colors.GREEN + (" 11-Detection attaque XSS/SQL/LFI" + " " * 13 + "12-Scanner le pcap avec SNORT\n") + colors.END


			pack = raw_input(colors.GREEN + "\nChoisir une action sur le pcap > " + colors.END)
			print "\n"


			if pack == "1":

				infos = os.popen("capinfos '%s'" % pcap).read()
				print colors.GREEN + ("informations") + colors.END
				print (infos)	
			elif pack == "2":

				string = raw_input(colors.YELLOW + "Recherche de pattern : " + colors.END)

				print colors.GREEN + ("Resultats\n") + colors.END
				response = subprocess.call("ngrep -q -I '%s' | grep -i '%s' | sort | uniq -c" % (pcap, string),
											shell=True)


			elif pack == "3":
				request = os.popen("tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method == \"GET\"' -r '%s' | sort | uniq |more" %pcap).read()
				print ("----------------------------------------------------------")
				print colors.RED + ("    Domaine            |               URI\n") + colors.END
				print ("----------------------------------------------------------")
				print (request)
				print ("----------------------------------------------------------")


			elif pack == "4":
				userA = os.popen(
					"tshark -Y 'http contains \"User-Agent:\"' -T fields -e http.user_agent -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print colors.RED + ("Occurence | User agent\n") + colors.END
				print (userA)
				
			elif pack == "5":
				print colors.RED + "Requetes DNS" + colors.END
				request = os.popen("tshark -nr '%s' -T fields -e ip.src -e dns.qry.name -e dns.resp.addr -Y 'dns.flags.response==0' | sort | uniq -c | sort -nr" %pcap).read()
				print ("----------------------------------------------------------")
				print colors.RED + ("    IP source            |            Domaine\n") + colors.END
				print ("----------------------------------------------------------")
				print (request)
				print ("----------------------------------------------------------")
			

			elif pack == "6":

				print ("\na- IO Statistics")
				print ("b- Arborescence")
				print ("c- Conversation(TCP,IP,UDP)")
				print ("d- TOUT\n")

				itachi = raw_input("\nChoix: > ")

				if itachi == "a":
					io = subprocess.call("tshark -r '%s' -qz io,stat,10,tcp,udp,icmp,ip,smtp,smb,arp,browser" %pcap , shell=True)

				elif itachi == "b":
					prototree = subprocess.call("tshark -r '%s' -qz io,phs" %pcap, shell=True)

				elif itachi == "c": # Protocol if : else control Error..

					print colors.RED + ("TCP Conversation\n") + colors.END

					tcpt = subprocess.call("tshark -r '%s' -qz conv,tcp" % (pcap), shell=True)

					print colors.RED + ("IP Conversation\n") + colors.END

					ipt = subprocess.call("tshark -r '%s' -qz conv,ip" % (pcap), shell=True)

					print colors.RED + ("UDP Conversation\n") + colors.END

					udpt = subprocess.call("tshark -r '%s' -qz conv,udp" % (pcap), shell=True)

				elif itachi == "d":

					print colors.RED + ("TOUT\n") + colors.END
					conver = pyshark.FileCapture('%s' %pcap)

					def conversat(converpack):
						try:

							proto     = converpack.transport_layer
							src_addr  = converpack.ip.src
							src_port  = converpack[converpack.transport_layer].srcport
							dst_addr  = converpack.ip.dst
							dst_port  = converpack[converpack.transport_layer].dstport
							print ("Protocol: " '%s' "  -  ""Source: " '%s'" - PORT: "'%s' " ----> " "Destination: " '%s'" - PORT: "'%s' %(proto,src_addr,src_port,dst_addr,dst_port))

						except AttributeError:
							pass
					conver.apply_on_packets(conversat, timeout=50)


			elif pack == "7":

				print colors.RED + "Occurence | Port" + colors.END

				port = subprocess.call("tcpdump -nn -r '%s' -p 'tcp or udp' | awk -F' ' '{print $5}' | awk -F'.' '{print $5}' | sed 's/:/ /g'  | sort | uniq -c | sort -n" %pcap, shell=True)

			elif pack == "8":

				print colors.RED + "Liste des IP\n" + colors.END

				ipls = os.popen("tcpdump -nn -r '%s' -p 'tcp or udp'" %pcap).read()
				ipreg = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipls)

				st2 = set()
				uniq2 = [allip for allip in ipreg if allip not in st2 and not st2.add(allip)]

				for one in uniq2:
					print  (colors.YELLOW+"[+]"+colors.END+colors.BLUE +one+colors.END )

				
			elif pack == "9":

				print colors.YELLOW + "Filtre Wireshark" + colors.END

				filt = raw_input("Filtre > ")

				try:
					filtr = pyshark.FileCapture(pcap, display_filter='%s' %filt)

					for tr in filtr:
						print (tr)
				except:
					return
					
			elif pack == "10":
				top10 = os.popen("tshark -T fields -e http.host -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print colors.GREEN + ("Sites visites\n\nOccurence | Domaine") + colors.END
				print (top10)




			elif pack == "11":

				sql = ['UNION', 'SELECT', 'CONCAT', 'FROM', 'union', 'select', '@@version', 'substring', 'information',
					   'table_name', 'from', 'convert', 'concat']
				xss = ['%3Cscript%3E', 'ALeRt', 'ScriPt', '<script>', '</script>', 'alert(\'xss\')', 'XSS', 'xss',
					   'alert(', '\';alert', 'onerror', 'document.cookie', 'onmouseover', '<img>', '<SCRIPT>',
					   'SCscriptIPT', 'scSCRIPTipt', 'onfocus=alert', 'alALERTert', 'String.fromCharCode']
				lfi = ['../../', '..//..//', '../', '/etc/passwd', '/etc/', '/proc/self/environ', '%00',
					   'php://filter/convert.base64-encode/resource=', 'cat /etc/passwd', 'system()', 'exec()',
					   'whoami']


				openpack = open(pcap)
				pcap11 = dpkt.pcap.Reader(openpack)
				app = []

				print (colors.YELLOW+"\nDetection attaque XSS/SQL/LFI\n\nAttaque:\n[+XSS]\n[+LFİ]\n[+SQLİ]\n"+colors.END)

				for ts, buf in pcap11:
					eth = dpkt.ethernet.Ethernet(buf)
					ip = eth.data
					tcp = ip.data

					try:

						if tcp.dport == 80 and len(tcp.data) > 0:
							http = dpkt.http.Request(tcp.data)
							asd = str(http.uri)
							tata = app.append(asd)

							for url in app:
								pass

							for vuln in sql:
								if vuln in url:
									try:
										print colors.RED + "Injection SQL: " + colors.END, url

									except:
										AttributeError


							for vuln2 in xss:
								if vuln2 in url:
									try:
										print colors.RED + "Attaque XSS: " + colors.END, url
									except:
										AttributeError

							for vuln3 in lfi:
								if vuln3 in url:
									try:
										print colors.RED + "Attaque par LFI: " + colors.END, url
									except:
										AttributeError

					except:
						AttributeError
			elif pack == "12":

				print colors.RED + "Scan snort" + colors.END
				tcpt = subprocess.call("snort -c /etc/snort/snort.conf -q -A Console -r %s" % (pcap), shell=True)
				process = subprocess.call(command, '%s', shell=True)
				process.wait()
				print process.returncode
			elif pack == "13":

				print colors.RED + "Scan suricata" + colors.END
				tcpt = subprocess.call("suricata -c /etc/suricata/suricata.yaml -r %s" % (pcap), shell=True)
				process = subprocess.call(command, '%s', shell=True)
				process.wait()
				print process.returncode
				
def capture():
		interfaces = os.popen("tshark -D |awk '{print $2'}").read()
		print (interfaces)
		interface = raw_input("Choisissez votre interface : ")
		duration = raw_input("Choisissez la durée (en secondes) : ")
		fichier = raw_input("Choisissez un nom pour le pcap de sortie :")
		with open(fichier,'w') as i:
			udpt = subprocess.Popen(["tshark -V -li '%s' -w '%s' -a duration:'%s'" % (interface, fichier, duration) ], shell=True)
		fichier.close()
	
def rule2pcap():
		print colors.GREEN +("\n----------------------------------Créer un pcap à partir d'une règle qui est dans un fichier txt-------------------------------------------------\n") + colors.END
		txt = raw_input("Chemin vers le fichier txt(chemin complet) > ")
		fichier = raw_input("Choisissez un nom pour le pcap de sortie :")
		with open(txt,"r") as infile, open(fichier,"wb") as outfile:
			udpt = subprocess.Popen(["./r2a.py -c /etc/snort/snort.conf -f '%s' -w '%s'" % (txt, fichier) ], shell=True)
			print colors.RED + "Créer un pcap à partir de regles contenues dans un fichier txt" + colors.END


def action2pcap():
		pcap = raw_input("pcap à utiliser (chemin complet) > ")
		if pcap == pcap:
			control = (os.popen("file " '%s' %pcap)).read()
			if 'capture file' in control:
				pass
			else:
				print colors.BOLD + ("Verifier le chemin du pcap") + colors.END
				sys.exit()
		while True:

			print "\n"
			print colors.BLUE + (" " * 25 + "|-Que souhaitez-vous faire? -|\n") + colors.END
			print colors.GREEN + (" 1-Informations sur le PCAP" + " " * 13 + "2-Reparer un pcap\n") + colors.END
			print colors.GREEN + (" 3-Preparer un pcap pour Splunk" + " " * 9 + "4-Créer un rapport html\n") + colors.END
			
			
			pack = raw_input(colors.GREEN + "\nChoisir une action sur le pcap > " + colors.END)
			print "\n"
			
			
			if pack == "1":

				infos = os.popen("capinfos '%s'" % pcap).read()
				print colors.GREEN + ("informations") + colors.END
				print (infos)	
			elif pack == "2":

				fichier = raw_input(colors.YELLOW + "Entrez le nom du pcap en sortie : " + colors.END)
				with open(fichier,'wb') as i:
					udpt = subprocess.Popen(["pcapfix '%s' -o '%s' -v" % (pcap, fichier) ], shell=True)
				fichier.close()
			elif pack == "3":
				fichier = raw_input(colors.YELLOW + "Entrez le nom du csv en sortie : " + colors.END)
				with open(fichier, 'wb') as csvfile:
					csvFormat = ['_time','eth_src','eth_dst','eth_type','protocol','ip_version','ip_id','ip_len','ip_proto','ip_ttl','ip_flags','ip_src','ip_dst','icmp_code','icmp_type','icmp_resptime','udp_srcport','udp_dstport','dns_id','dns_qry_type','dns_resp_type','dns_qry_name','dns_a','tcp_stream','tcp_seq','win_size','syn','ack','tcp_srcport','tcp_dstport','psh','fin','rst','info','rtt','vland_id','http_request_method','http_host','http_request_version','http_user_agent','http_server','http_response_code','http_response_phrase','http_content_type','http_referer','http_cookie','http_request_full_uri']
					#cw = csv.writer(csvfile,delimiter=",")
					csvConf = {'dialect' : 'excel'}
					csvWriter = csvDictWriterWrapper(csvFormat, **csvConf)
					if not options.append :
						outputFileWriter.write(csvWriter.produceUnicodeCsvHeader())

					tcpt = subprocess.Popen("tshark -r '%s' -T fields -E separator=, -E occurrence=a -E quote=d -e frame.time -e eth.src -e eth.dst -e eth.type -e _ws.col.Protocol -e ip.version -e ip.id -e ip.len -e ip.proto \
	-e ip.ttl -e ip.flags -e ip.src -e ip.dst -e icmp.code -e icmp.type -e icmp.resptime -e udp.srcport -e udp.dstport -e dns.id -e dns.qry.type -e dns.resp.type -e dns.qry.name -e dns.a \
	-e tcp.stream -e tcp.seq -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack  -e tcp.srcport -e tcp.dstport -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e _ws.col.Info -e tcp.analysis.ack_rtt -e vlan.id \
	-e http.request.method -e http.host -e http.request.version -e http.user_agent -e http.server \
	-e http.response.code -e http.response.phrase -e http.content_type -e http.referer -e http.cookie -e http.request.full_uri" % (pcap))
					#for line in tcpt:
						#cw.writerow(line)
					#print (line)	
					
try:
	if __name__ == '__main__':
		select = raw_input("Selection> ")

		if select == "1":
			packet()
		if select == "2":
			capture()
		if select == "3":
			rule2pcap()
		if select == "4":
			action2pcap()
except:
	KeyboardInterrupt
	print ("Exit Tool..")
