#!/usr/bin/env bash

recon(){
	mkdir ./$1/$foldername/dns-recon-raw
	touch ./$1/$foldername/$1_subdomains.txt

	echo "[+] Running Sublist3r on $1"
 	python ~/tools/Sublist3r/sublist3r.py -d $1 -t 10 -o ./$1/$foldername/$1_subdomains.txt | tee ./$1/$foldername/dns-recon-raw/$1_sublist3r.txt 
	firstToolFound=$(sort -u ./$1/$foldername/$1_subdomains.txt | wc -l)
	echo "[+] Sublist3r found $firstToolFound subdomains. Raw output at ./$1/$foldername/dns-recon-raw/$1_sublist3r.txt" 

	echo "[+] Running Certspotter on $1"
  	curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 | tee -a ./$1/$foldername/$1_subdomains.txt ./$1/$foldername/dns-recon-raw/$1_certspotter.txt
	secondToolFound=$(sort -u ./$1/$foldername/dns-recon-raw/$1_certspotter.txt | wc -l)
	totalFound1=$(sort -u ./$1/$foldername/$1_subdomains.txt | wc -l)
	echo "[+] Certspotter found $secondToolFound subdomains ($(expr $totalFound1 - $firstToolFound) new). Raw output at ./$1/$foldername/dns-recon-raw/$1_certspotter.txt"
	
	echo "[+] Running amass on $1"
  	amass -d $1 | tee -a ./$1/$foldername/$1_subdomains.txt ./$1/$foldername/$1_amass.txt
	thirdToolFound=$(sort -u ./$1/$foldername/$1_amass.txt | wc -l)
	totalFound2=$(sort -u ./$1/$foldername/$1_subdomains.txt | wc -l)
	echo "[+] amass found $thirdToolFound subdomains ($(expr $totalFound2 - $totalFound1) new). Raw output at ./$1/$foldername/dns-recon-raw/$1_amass.txt"
  	
	echo "[+] Running Subfinder on $1"
  	subfinder --silent -d $1 | tee -a ./$1/$foldername/$1_subdomains.txt ./$1/$foldername/dns-recon-raw/$1_subfinder.txt
	fourthToolFound=$(sort -u ./$1/$foldername/dns-recon-raw/$1_subfinder.txt | wc -l)
	totalFound3=$(sort -u ./$1/$foldername/$1_subdomains.txt | wc -l)
	echo "[+] subfinder found $fourthToolFound subdomains ($(expr $totalFound3 - $totalFound2) new). Raw output at ./$1/$foldername/dns-recon-raw/$1_subfinder.txt"

	echo "[+] Checking Common Crawl for $1"
	python3 ~/tools/cc.py/cc.py -o ./$1/$foldername/dns-recon-raw/$1_commoncrawl.txt $1
	cat ./$1/$foldername/dns-recon-raw/$1_commoncrawl.txt | cut -d '/' -f 3 | sort -u >> ./$1/$foldername/$1_subdomains.txt
	sort -u -o ./$1/$foldername/$1_commoncrawl_urls.txt ./$1/$foldername/dns-recon-raw/$1_commoncrawl.txt
	fifthToolFound=$(cat ./$1/$foldername/dns-recon-raw/$1_commoncrawl.txt | cut -d '/' -f 3 | sort -u | wc -l)
	totalFound4=$(sort -u ./$1/$foldername/$1_subdomains.txt | wc -l)
	echo "[+] Common Crawl found $fifthToolFound subdomains ($(expr totalFound4 - totalFound3) new). Raw output at ./$1/$foldername/dns-recon-raw/$1_commoncrawl.txt"
	
	sort -u -o ./$1/$foldername/$1_subdomains.txt ./$1/$foldername/$1_subdomains.txt
	discovery $1
}

discovery(){
	hostresolves $1
	shodanvuln $1
	nmapTop1000TCP $1
	nmapCommonUDP $1
  	screenshot $1
	passivecontentdisco $1
	activecontentdisco $1
	cat ./$1/$foldername/$1_subdomains.txt | sort -u | while read line; do
    		sleep 1
    		#discovercontent $line
    	#	report $1 $line
    	#	echo "$line report generated"
    		sleep 1
  	done
}

hostresolves(){
	cat ./$1/$foldername/$1_subdomains.txt | while read line; do
	ip=$(dig +short $line|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1)
  	if [ $ip ]
	then
		echo "$line resolves to $ip"
      		echo "$ip:$line" >> ./$1/$foldername/$1_ips-to-hostnames.txt
      		echo $ip >> ./$1/$foldername/$1_ips.txt
		echo $line >> ./$1/$foldername/$1_resolvable_subdomains.txt
	else
		echo "$line was unreachable"
      		echo "<b>$line</b> was unreachable<br>" >> ./$1/$foldername/unreachable.html
	fi
	done

	sort -u -o ./$1/$foldername/$1_ips-to-hostnames.txt ./$1/$foldername/$1_ips-to-hostnames.txt
	sort -u -o ./$1/$foldername/$1_ips.txt ./$1/$foldername/$1_ips.txt
}

shodanvuln(){
	cat ./$1/$foldername/$1_ips.txt | while read line; do
		echo "[+] Checking Shodan for vulnerabilities on $line"
        	shodan stats --limit 1000 --facets vuln ip:$line | tee -a ./$1/$foldername/$1_shodan-vuln-results.txt
	done
}

nmapTop1000TCP(){
	mkdir ./$1/$foldername/nmap-raw
	echo "[+] Nmap service scanning top 1000 TCP ports on domains"
	nmap -sV -Pn -T3 --open --version-intensity 5 -iL ./$1/$foldername/$1_reachable_hostnames.txt -oA ./$1/$foldername/nmap-raw/top1000TCP
	xsltproc ./$1/$foldername/nmap-raw/top1000TCP.xml -o ./$1/$foldername/nmap_top1000TCP_parsed.htm
}

nmapCommonUDP(){
	echo "[+] Nmap service scanning UDP ports 53, 161, and 500 on domains"
	nmap -sV -Pn --open --version-intensity 5 -sU -O --max-rate 15000 -Pn -T3 -p 53,161,500 -iL ./$1/$foldername/$1_reachable_hostnames.txt -oA ./$1/$foldername/nmap-raw/commonUDP
	xsltproc ./$1/$foldername/nmap-raw/commonUDP.xml -o ./$1/$foldername/nmap_commonUDP_parsed.htm
}

screenshot(){
    	echo "[+] Launching Eyewitness"
	eyewitness -x ./$1/$foldername/nmap-raw/top1000TCP.xml --all-protocols --timeout 30 --no-prompt -d ./$1/$foldername/eyewitness_top1000TCP
}

passivecontentdisco(){
	cat ./$1/$foldername/$1_ips.txt | while read line; do
		echo "[+] Scanning the Wayback machine for $line URLs"
		waybackurls $line >> ./$1/$foldername/$1_wayback_urls.txt
	done
	sort -u -o ./$1/$foldername/$1_wayback_urls.txt ./$1/$foldername/$1_wayback_urls.txt
}

activecontentdisco(){
	#make a list of all webserver URLs using Eyewitness output
	cat ./$1/$foldername/eyewitness_top1000TCP/open_ports.csv | grep $1 | cut -d ',' -f 1 > ./$1/$foldername/webserver-urls.txt
	echo "[+] Running content discovery against webservers"
	cat ./$1/$foldername/webserver-urls.txt | while read line; do
	sleep 1
	gobuster -w /usr/share/wordlists/content_discovery_all.txt -s 200,301,307 -t 100 -u $line
	sleep 1
	done
}

logo(){
  #can't have a bash script without a cool logo :D
  echo "

 .____    .__             .__         __________                            
 |    |   |__|__  __ ____ |  | ___.__.\______   \ ____   ____  ____   ____  
 |    |   |  \  \/ // __ \|  |<   |  | |       _// __ \_/ ___\/  _ \ /    \ 
 |    |___|  |\   /\  ___/|  |_\___  | |    |   \  ___/\  \__(  <_> )   |  \
 |_______ \__| \_/  \___  >____/ ____| |____|_  /\___  >\___  >____/|___|  /
         \/             \/     \/             \/     \/     \/           \/ 

                                                      "
}

main(){
  logo

  if [ -d "./$1" ]
  then
    echo "This is a known target."
  else
    mkdir ./$1
  fi
  mkdir ./$1/$foldername
  mkdir ./$1/$foldername/reports/

    recon $1
}

if [[ -z $@ ]]; then
  echo "Error: no targets specified."
  echo "Usage: ./lazyrecon.sh <target>"
  exit 1
fi

path=$(pwd)
foldername=recon-$(date +"%Y-%m-%d")
main $1
