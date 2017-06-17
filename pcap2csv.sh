#!/bin/bash
#Daniel Schwartz
#This script converts pcap files to a csv file using tshark 1.11.x and 1.12 
#Created: May 2015
#Updated: January 2017 by Cedric Hien
#Version 1.4m



if test -z "$1"
then
	chemin="$0"
	echo $chemin
	single=0
else
	if [ -d "$1" ]; then
		chemin="$1";
		echo $chemin
		single=0
	elif [ -f "$1" ]; then
		file=$1
		chemin=$(dirname "$1")
		echo $chemin
		single=1
	fi
fi

if [ $single==1 ]
then
	echo $index \
	$file
	echo "_time","eth_src","eth_dst","eth_type","protocol","ip_version","ip_id","ip_len","ip_proto","ip_ttl","ip_flags","ip_src","ip_dst","icmp_code","icmp_type","icmp_resptime","udp_srcport","udp_dstport", \
	"dns_id","dns_qry_type","dns_resp_type","dns_qry_name","dns_a", \
	"tcp_stream","tcp_seq","win_size","syn","ack","tcp_srcport","tcp_dstport","psh","fin","rst","info","rtt","vland_id", \
	"http_request_method","http_host", \
	"http_request_version","http_user_agent","http_server","http_response_code","http_response_phrase","http_content_type","http_referer","http_cookie","http_request_full_uri" > "$chemin"/"$(basename "$file")".csv
	tshark -r "$file" -T fields -E separator=, -E occurrence=a -E quote=d -e frame.time -e eth.src -e eth.dst -e eth.type -e _ws.col.Protocol -e ip.version -e ip.id -e ip.len -e ip.proto \
	-e ip.ttl -e ip.flags -e ip.src -e ip.dst -e icmp.code -e icmp.type -e icmp.resptime -e udp.srcport -e udp.dstport -e dns.id -e dns.qry.type -e dns.resp.type -e dns.qry.name -e dns.a \
	-e tcp.stream -e tcp.seq -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack  -e tcp.srcport -e tcp.dstport -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e _ws.col.Info -e tcp.analysis.ack_rtt -e vlan.id \
	-e http.request.method -e http.host -e http.request.version -e http.user_agent -e http.server \
	-e http.response.code -e http.response.phrase -e http.content_type -e http.referer -e http.cookie -e http.request.full_uri >> "$chemin"/"$(basename "$file")".csv
else
        find "$chemin" -maxdepth 1 -type d ! -path "$chemin" -print0 | while IFS= read -r -d '' full_index
        do
                index=$(basename $full_index)
                find "$chemin/$index" -maxdepth 1 -type f \( -iname *.pcap -o -iname *.pcapng \) -print0 | while IFS= read -r -d '' file
                do
                        echo $index \
                        $file
                        echo "_time","eth_src","eth_dst","eth_type","protocol","ip_version","ip_id","ip_len","ip_proto","ip_ttl","ip_flags","ip_src","ip_dst","icmp_code","icmp_type","icmp_resptime","udp_$
                        "dns_id","dns_qry_type","dns_resp_type","dns_qry_name","dns_a", \
                        "tcp_stream","tcp_seq","win_size","syn","ack","tcp_srcport","tcp_dstport","psh","fin","rst","info","rtt","vland_id", \
                        "http_request_method","http_host", \
                        "http_request_version","http_user_agent","http_server","http_response_code","http_response_phrase","http_content_type","http_referer","http_cookie","http_request_full_uri" > "$che$
                        tshark -r "$file" -T fields -E separator=, -E occurrence=a -E quote=d -e frame.time -e eth.src -e eth.dst -e eth.type -e _ws.col.Protocol -e ip.version -e ip.id -e ip.len -e ip.pr$
                        -e ip.ttl -e ip.flags -e ip.src -e ip.dst -e icmp.code -e icmp.type -e icmp.resptime -e udp.srcport -e udp.dstport -e dns.id -e dns.qry.type -e dns.resp.type -e dns.qry.name -e dn$
                        -e tcp.stream -e tcp.seq -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack  -e tcp.srcport -e tcp.dstport -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e _ws.col.Info $
                        -e http.request.method -e http.host -e http.request.version -e http.user_agent -e http.server \
                        -e http.response.code -e http.response.phrase -e http.content_type -e http.referer -e http.cookie -e http.request.full_uri >> "$chemin"/"$index"/"$(basename "$file")".csv
                done
        done
fi
#for file in `find $chemin -maxdepth 1 -name *.pcap 2>/dev/null`
#do
#	tshark -r "$file" -T fields -e frame.time -e tcp.stream -e ip.src -e ip.dst -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack -e tc-e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e ip.ttl -e _ws.col.Info -e tcp.analysis.ack_rtt -e vlan.idp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e ip.ttl -e _ws.col.Info -e tcp.analysis.ack_rtt -e vlan.id > /BACKUP/00_DEPOT_LOG_H24/PCAP/"$(basename "$file")".csv/BACKUP/00_DEPOT_LOG_H24/PCAP/"$(basename "$file")".csv
#done
