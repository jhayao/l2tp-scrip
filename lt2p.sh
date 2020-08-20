#!/bin/bash
echo Please Provide server info: 
read -p 'VirtualHubName: ' VirtualHubName
read -p 'VirtualHubPass: ' VirtualHubPass
read -p 'PreSharedKey: ' PreSharedKey
read -p 'OpenVPN_Port: ' OpenVPN_Port


apt update && apt upgrade -y &> /dev/null
apt install nano wget curl zip unzip tar gzip bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 -y &> /dev/null
apt install build-essential libreadline-dev libssl-dev libncurses-dev zlib1g-dev -y &> /dev/null
apt install apache2 -y &> /dev/null

wget -qO softether.tar.gz "https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/archive/v4.34-9745-beta.tar.gz" && tar xzf softether.tar.gz && rm -f softether.tar.gz && mv SoftEtherVPN_Stable* SE
cd SE && ./configure && make && make install
cp debian/softether-vpnserver.init /etc/init.d/vpnserver && chmod +x /etc/init.d/vpnserver
vpnserver start &> /dev/null
chkconfig vpnserver on &> /dev/null || systemctl enable vpnserver &> /dev/null
vpncmd localhost /SERVER /CMD HubCreate "$VirtualHubName" /PASSWORD:"$VirtualHubPass"
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD NatEnable
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD SecureNatEnable
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD DhcpEnable
DefIP_ID="$(vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD IpTable | grep "ID" | head -n1 | cut -d "|" -f2)" && vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD IpDelete $DefIP_ID
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD SecureNatHostSet /MAC:none /IP:"172.16.0.1" /MASK:"255.255.0.0"
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD DhcpSet /START:"172.16.0.10" /END:"172.16.255.254" /MASK:"255.255.0.0" /EXPIRE:"10" /GW:"172.16.0.1" /DNS:"1.1.1.1" /DNS2:"1.0.0.1" /DOMAIN:none /LOG:yes

sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf && sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf && echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-softether.conf && sysctl --system &> /dev/null
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD ServerCipherSet AES128-SHA

vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD IPSecEnable /L2TP:yes /L2TPRAW:yes /ETHERIP:yes /PSK:"$PreSharedKey" /DEFAULTHUB:"$VirtualHubName"
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD SstpEnable yes &> /dev/null

vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD OpenVpnEnable yes /PORTS:"$OpenVPN_Port"

vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD MakeCert /CN:"Bon-chan SoftEther Service" /O:"BonvScripts SoftEther Tutorial" /OU:"github.com/Bonveio/BonvScripts" /C:PH /ST:NCR /L:"Caloocan" /SERIAL:none /EXPIRES:9999 /SAVECERT:"~/ca.crt" /SAVEKEY:"~/ca.key"
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD ServerCertSet /LOADCERT:"~/ca.crt" /LOADKEY:"~/ca.key"
echo -e "client\ndev tun\nproto udp\nremote $(curl -4s http://ipinfo.io/ip) $OpenVPN_Port\nremote-cert-tls server\ncipher none\nauth SHA1\nconnect-retry infinite\nresolv-retry infinite\nfloat\npersist-remote-ip\npersist-tun\nkeysize 0\nnobind\nmute-replay-warnings\nauth-user-pass\nauth-nocache\nverb 1\nsetenv CLIENT_CERT 0\n<ca>\n$(cat ~/ca.crt)\n</ca>" > ~/client.ovpn
mv client.ovpn /var/www/html/

read -p 'VPNUsername: ' VPNUsername
read -p 'VPNPassword: ' VPNPassword
read -p 'SetMaxSession: ' SetMaxSession 

vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD UserCreate $VPNUsername /GROUP:none /REALNAME:none /NOTE:none &> /dev/null && vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD UserPasswordSet $VPNUsername /PASSWORD:"$VPNPassword" &> /dev/null
vpncmd localhost /SERVER /ADMINHUB:"$VirtualHubName" /CMD SetMaxSession $SetMaxSession

apt install squid -y
Proxy_Port='81'
echo -e "acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32\nhttp_access allow VPN\nhttp_access deny all\nhttp_port 0.0.0.0:$Proxy_Port\nacl all src 0.0.0.0/0.0.0.0\nno_cache deny all\ndns_nameservers 1.1.1.1 1.0.0.1\nvisible_hostname localhost" > /etc/squid/squid.conf
service squid restart
echo -e "client\ndev tun\nproto tcp\nremote $(curl -4s http://ipinfo.io/ip) 443\nremote-cert-tls server\ncipher none\nauth SHA1\nconnect-retry infinite\nresolv-retry infinite\npersist-remote-ip\npersist-tun\nkeysize 0\nnobind\nmute-replay-warnings\nauth-user-pass\nauth-nocache\nverb 1\nsetenv CLIENT_CERT 0\nhttp-proxy $(curl -4s http://ipinfo.io/ip) $Proxy_Port\nhttp-proxy-option CUSTOM-HEADER Host www.googleapis.com\n<ca>\n$(cat ~/ca.crt)\n</ca>" > ~/client_tcp.ovpn
mv client_tcp.ovpn /var/www/html/

read -p 'Server Password: ' ServerPassword


vpncmd localhost /SERVER /CMD ServerPasswordSet $ServerPassword
