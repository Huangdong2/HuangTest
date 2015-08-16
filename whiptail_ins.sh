#!/bin/bash
#

apt_get_y_install (){

if [[ "$1" != "" ]]; then
  apt_package_install_list=()
  while [[ "$1" != "" ]]; do
    pkg=$1
    shift
    package_version="$(dpkg -s ${pkg} 2>&1 | grep 'Version:' | cut -d " " -f 2)"
  	if [[ -n "${package_version}" ]]; then
  		space_count="$(expr 20 - "${#pkg}")" #11
  		pack_space_count="$(expr 30 - "${#package_version}")"
  		real_space="$(expr ${space_count} + ${pack_space_count} + ${#package_version})"
  		printf " * $pkg %${real_space}.${#package_version}s ${package_version}\n"
  	else
      echo " *" $pkg [not installed]
      apt_package_install_list+=($pkg)
    fi
    if [[ ${#apt_package_install_list[@]} = 0 ]]; then
  		echo -e "No apt packages to install.\n"
  	else
      echo "Installing apt-get packages..."
  		apt-get -qqy install ${apt_package_install_list[@]} # > /dev/null 2>&1
    fi
  done
fi

}

questions (){

  PKG_OK=$(dpkg-query -W --showformat='${Status}\n' whiptail|grep "install ok installed")
  echo Checking for whiptail: $PKG_OK
  if [ "" == "$PKG_OK" ]; then
    echo "whiptail non installé. Configuration de whiptail."
    apt-get update
    apt_get_y_install whiptail
  fi

  if [[ -z $1 ]]; then
    while [ "x$serverIP" == "x" ]
    do
      serverIP=$(whiptail --title "Server IP" --backtitle "$back_title" --inputbox "Veuillez saisir l'IP du serveur" --nocancel 10 50 3>&1 1>&2 2>&3)
    done
  else
    serverIP=$1
  fi

  if [[ -z $2 ]]; then
    while [ "x$HOSTNAMESHORT" == "x" ]
    do
      HOSTNAMESHORT=$(whiptail --title "Short Hostname" --backtitle "$back_title" --inputbox "Veuillez indiquer un alias au serveur" --nocancel 10 50 3>&1 1>&2 2>&3)
    done
  else
    HOSTNAMESHORT=$2
  fi

  if [[ -z $3 ]]; then
    while [ "x$HOSTNAMEFQDN" == "x" ]
    do
      HOSTNAMEFQDN=$(whiptail --title "Fully Qualified Hostname" --backtitle "$back_title" --inputbox "Veuillez indiquer le nom complet du serveur" --nocancel 10 50 3>&1 1>&2 2>&3)
    done
  else
    HOSTNAMEFQDN=$3
  fi

  if [[ -z $4 ]]; then
    while [ "x$web_server" == "x" ]
    do
      web_server=$(whiptail --title "Web Server" --backtitle "$back_title" --nocancel --radiolist "Quelle serveur Web voulez-vouys installer ?" 10 50 2 "Apache" "(default)" ON "NginX" "" OFF 3>&1 1>&2 2>&3)
    done
  else
    web_server=$4
  fi

  if [[ -z $5 ]]; then
    while [ "x$mail_server" == "x" ]
    do
      mail_server=$(whiptail --title "Mail Server" --backtitle "$back_title" --nocancel --radiolist "Quel serveur de Mail voulez-vous installer ?" 10 50 2 "Dovecot" "(default)" ON "Courier" "" OFF 3>&1 1>&2 2>&3)
    done
  else
    mail_server=$5
  fi

  if [[ -z $6 ]]; then
    while [ "x$sql_server" == "x" ]
    do
      sql_server=$(whiptail --title "SQL Server" --backtitle "$back_title" --nocancel --radiolist "Quelle base de donnée voulez-vous insaller ?" 10 50 2 "MySQL" "(default)" ON "MariaDB" "" OFF 3>&1 1>&2 2>&3)
    done
  else
    sql_server=$6
  fi

  if [[ -z $7 ]]; then
    while [ "x$mysql_pass" == "x" ]
    do
      mysql_pass=$(whiptail --title "MySQL Root Password" --backtitle "$back_title" --inputbox "Veuillez indiquer le mot de passe root SQL" --nocancel 10 50 3>&1 1>&2 2>&3)
    done
  else
    mysql_pass=$7
  fi

  if [[ -z $8 ]]; then
    if (whiptail --title "Install Quota" --backtitle "$back_title" --yesno "Configurer Quotas Utilisateurs?" 10 50) then
      quota=Yes
    else
      quota=No
    fi
  else
    quota=$8
  fi

  if [[ -z $9 ]]; then
    if (whiptail --title "Install Mailman" --backtitle "$back_title" --yesno "Configurer Mailman?" 10 50) then
      mailman=Yes
    else
      mailman=No
    fi
  else
    mailman=$9
  fi

  if [[ -z ${10} ]]; then
    if (whiptail --title "Install Jailkit" --backtitle "$back_title" --yesno "Configurer Jailkits Utilisateur ?" 10 50) then
      jailkit=Yes
    else
      jailkit=No
    fi
  else
    jailkit=${10}
  fi

    if [[ -z ${11} ]]; then
      while [ "x$phpmyadmin_app_password" == "x" ]
      do
        phpmyadmin_app_password=$(whiptail --title "phpmyadmin app Password" --backtitle "$back_title" --inputbox "enter your phpmyadmin application password" --nocancel 10 50 3>&1 1>&2 2>&3)
      done
    else
      phpmyadmin_app_password=${11}
    fi

}

replace_first_occurrence (){
  # echo ......
  # echo sed -e \"0,/$1/ s/$1/$2/\" -i $3
  # echo ......
  sed -e "0,/$1/ s/$1/$2/" -i $3
}

replace_second_occurrence (){
  replace_first_occurrence "$1" "$flag_word" $3
  replace_first_occurrence "$1" "$2" $3
  sed -i "s/$flag_word/$1/" $3
}

replace_third_occurrence (){
  replace_first_occurrence "$1" "$flag_word" $3
  replace_second_occurrence "$1" "$2" $3
}

update_rc_d (){
  update-rc.d $1 start 20 $2 . stop 20 $3 .
  # update-rc.d chinaMTU start 20 S . stop 20 0 6 .
}

git_clone (){
  [ ! -d $2 ] && git clone https://github.com/$1/$2.git
}

swap_creation (){
# swap creation

# https://gist.githubusercontent.com/peterchester/4537ed05a790045dd11f/raw/51121ac2d3a370e2c27032c9e14c0ca2bbf2b382/swap.sh

# Creates a 1gb swap image.
# https://www.digitalocean.com/community/tutorials/how-to-configure-virtual-memory-swap-file-on-a-vps

if [ -f /var/swap.img ]; then
	echo "Swap file already exists."
else
	touch /var/swap.img
	chmod 600 /var/swap.img
	dd if=/dev/zero of=/var/swap.img bs=1024k count=1000
	mkswap /var/swap.img
	swapon /var/swap.img
	echo "/var/swap.img    none    swap    sw    0    0" >> /etc/fstab
	sysctl -w vm.swappiness=30
	free
	echo "Swap created and added to /etc/fstab for boot up."
fi
}

merge_client (){
  #######################################################################
  #       Openvpn supports inline certs and keys
  #       so you have one client script, instead of script plus 4 keys and certs
  #
  #       This tool requires
  #       1) openvpn script, certs and keys are in same directory
  #       2) The names of openvpn script, certs and keys as follows
  #

  ca="ca.crt"
  cert_std="client.crt"
  key_std="client.key"
  cert="$1.crt"
  key="$1.key"
  tlsauth="ta.key"

  ########################################################################
  #	Backup to new subdirectory, just incase
  #
  # mkdir -p backup
  # cp $ca $cert $key $tlsauth $1.ovpn ./backup

  ########################################################################
  #	Delete existing call to keys and certs
  #
  	sed -i \
  	-e '/ca .*'$ca'/d'  \
  	-e '/cert .*'$cert'/d' \
  	-e '/key .*'$key'/d' \
  	-e '/cert .*'$cert_std'/d' \
  	-e '/key .*'$key_std'/d' \
  	-e '/tls-auth .*'$tlsauth'/d' $1.ovpn

  ########################################################################
  #	Add keys and certs inline
  #
  echo "" >> $1.ovpn
  echo "key-direction 1" >> $1.ovpn

  echo "" >> $1.ovpn
  echo "<ca>" >> $1.ovpn
  awk /BEGIN/,/END/ < ./$ca >> $1.ovpn
  echo "</ca>" >> $1.ovpn

  echo "" >> $1.ovpn
  echo "<cert>" >> $1.ovpn
  awk /BEGIN/,/END/ < ./$cert >> $1.ovpn
  echo "</cert>" >> $1.ovpn

  echo "" >> $1.ovpn
  echo "<key>" >> $1.ovpn
  awk /BEGIN/,/END/ < ./$key >> $1.ovpn
  echo "</key>" >> $1.ovpn

  echo "" >> $1.ovpn
  echo "<tls-auth>" >> $1.ovpn
  awk /BEGIN/,/END/ < ./$tlsauth >> $1.ovpn
  echo "</tls-auth>" >> $1.ovpn

  ########################################################################
  #	Delete key and cert files, backup already made hopefully
  #
  rm $ca $cert $key $tlsauth
}

merge_server (){
  #######################################################################
  #       Latest versions of Openvpn supports inline certs and keys
  #       One file, instead of script plus keys and certs
  #
  #       This tool assumes
  #       1) Openvpn script, certs plus keys are in same directory
  #       2) Certs are usually specified in Openvpn script like
  #          ca ca.crt
  #             or
  #          ca /etc/local/openvpn/ca.crt
  ########################################################################
  #  Name of certs and keys and server conf script
  #

  ca="ca.crt"
  cert="server.crt"
  key="server.key"
  tlsauth="ta.key"
  if [[ -f dh2048.pem ]]; then
    dh="dh2048.pem"
    dh_std="dh.pem"
  else
    dh="dh.pem"
    dh_std="dh2048.pem"
  fi
  ovpndest="server.conf"

  ########################################################################
  #   Backup to new subdirectory, just incase
  #
  # mkdir -p backup
  # cp $ca $cert $key $tlsauth $ovpndest $dh ./backup

  ########################################################################
  #   Delete existing call to keys and certs
  #
      sed -i \
      -e '/ca .*'$ca'/d'  \
      -e '/cert .*'$cert'/d' \
      -e '/key .*'$key'/d' \
      -e '/dh .*'$dh_std'/d' \
      -e '/dh .*'$dh'/d' \
      -e '/tls-auth .*'$tlsauth'/d' $ovpndest

  ########################################################################
  #   Add keys and certs inline
  #
  echo "" >> $ovpndest
  echo "key-direction 0" >> $ovpndest

  echo "" >> $ovpndest
  echo "<ca>" >> $ovpndest
  awk /BEGIN/,/END/ < ./$ca >> $ovpndest
  echo "</ca>" >> $ovpndest

  echo "" >> $ovpndest
  echo "<cert>" >> $ovpndest
  awk /BEGIN/,/END/ < ./$cert >> $ovpndest
  echo "</cert>" >> $ovpndest

  echo "" >> $ovpndest
  echo "<key>" >> $ovpndest
  awk /BEGIN/,/END/ < ./$key >> $ovpndest
  echo "</key>" >> $ovpndest

  echo "" >> $ovpndest
  echo "<tls-auth>" >> $ovpndest
  awk /BEGIN/,/END/ < ./$tlsauth >> $ovpndest
  echo "</tls-auth>" >> $ovpndest

  echo "" >> $ovpndest
  echo "<dh>" >> $ovpndest
  awk /BEGIN/,/END/ < ./$dh >> $ovpndest
  echo "</dh>" >> $ovpndest

  ########################################################################
  #   Delete key and cert files, backup already made hopefully
  #
  rm $ca $cert $key $tlsauth $dh
}

add_apt_repository_ubuntu (){
# deb http://download.nus.edu.sg/mirror/ubuntu/ trusty main
# deb-src http://download.nus.edu.sg/mirror/ubuntu/ trusty main
#add-apt-repository -y "deb http://sgp1.mirrors.digitalocean.com/ubuntu/"
# add-apt-repository -y "deb http://ftp.cuhk.edu.hk/pub/Linux/ubuntu/ $DISTRO main"
# echo "deb-src http://ftp.cuhk.edu.hk/pub/Linux/ubuntu/ $DISTRO main" >> /etc/apt/sources.list
# add-apt-repository -y "deb http://ap-southeast-1.clouds.archive.ubuntu.com/ubuntu/ $DISTRO main restricted universe multiverse"
# add-apt-repository -y "deb http://ap-southeast-1.clouds.archive.ubuntu.com/ubuntu/ $DISTRO-updates main restricted universe multiverse"
# add-apt-repository -y "deb http://ap-southeast-1.clouds.archive.ubuntu.com/ubuntu/ $DISTRO-security main restricted universe multivers"

add-apt-repository -y "deb mirror://mirrors.ubuntu.com/mirrors.txt $DISTRO main restricted universe multiverse"
add-apt-repository -y "deb mirror://mirrors.ubuntu.com/mirrors.txt $DISTRO-updates main restricted universe multiverse"
add-apt-repository -y "deb mirror://mirrors.ubuntu.com/mirrors.txt $DISTRO-backports main restricted universe multiverse"
add-apt-repository -y "deb mirror://mirrors.ubuntu.com/mirrors.txt $DISTRO-security main restricted universe multiverse"
apt-get update
}

add_apt_repository_mariadb (){
  if [[ -z $repository_mariadb_added ]]; then
    #Ajout de la clef mariaDB
    # apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
    the_keyserver='--keyserver hkp://keyserver.ubuntu.com:80'
    apt-key adv --quiet --recv-keys $the_keyserver 0xcbcb082a1bb943db
    #Ajout des repo && MAJ
    # add-apt-repository "deb http://ftp.igh.cnrs.fr/pub/mariadb/repo/5.5/debian $DISTRO main" && apt-get update
    # add-apt-repository "deb http://mirror.stshosting.co.uk/mariadb/repo/10.0/debian $DISTRO main" && apt-get update

    # default version
    MARIADB_VERSION='10.0'
    mirrors_digitalocean="mirrors.digitalocean.com/mariadb/repo/$MARIADB_VERSION/debian $DISTRO main"
    add-apt-repository -y "deb http://sgp1.$mirrors_digitalocean" && apt-get update
  else
    repository_mariadb_added='Yes'
  fi

}

chinaMTU_maker (){
cat > /etc/init.d/chinaMTU <<EOF
#! /bin/sh

#sudo ifconfig eth1 mtu 1480 && sudo service ssh restart && sudo /etc/init.d/networking stop && sudo /etc/init.d/networking start

### BEGIN INIT INFO
# Provides:          huang gen dong. harbin, china
# Required-Start:    mountkernfs \$local_fs urandom
# Required-Stop:     \$local_fs
# X-Start-Before:    \$network
# X-Stop-After:
# Default-Start:     S
# Default-Stop:      0 6
# Short-Description: MTU from 1500 to 1480
# Description:       MTU 1480 for china users
### END INIT INFO

# Carry out changing MTU when asked to by the system
case "\$1" in
  start)
    echo "Starting chinaMTU..."
    sed -i "s/netmask 255.255.255.0/&\n      mtu 1480/" /etc/network/interfaces
    ;;
  *)
    echo "Usage: \$0 start"
    exit 1
    ;;
esac

exit 0

EOF

  #review_file /etc/init.d/chinaMTU
  #review_file /etc/init.d/networking
  #review_file /etc/network/interfaces

  chmod 755 /etc/init.d/chinaMTU
  # update-rc.d chinaMTU defaults
  update_rc_d chinaMTU 'S' '0 6'
  # http://www.speedguide.net/articles/linux-broadband-tweaks-121
}

chinaMTU_pre_maker (){
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html
cat > /etc/network/if-pre-up.d/$1-mtu <<EOF
#!/bin/bash
ip link set dev $1 mtu $2
EOF
chmod +x /etc/network/if-pre-up.d/$1-mtu
}

iptables_firewall_rules (){

  # iptables -A INPUT -s 65.55.44.100 -p tcp --destination-port 25 -j DROP

  touch $1
  echo "*filter" > $1
  echo "" >> $1
  echo "#  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0" >> $1
  echo "-A INPUT -i lo -j ACCEPT" >> $1
  echo "-A INPUT -d 127.0.0.0/8 -j REJECT" >> $1
  echo "" >> $1
  echo "#  Accept all established inbound connections" >> $1
  echo "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $1
  echo "" >> $1
  echo "#  Allow all outbound traffic - you can modify this to only allow certain traffic" >> $1
  echo "-A OUTPUT -j ACCEPT" >> $1
  echo "" >> $1
  echo "#  Allow HTTP and HTTPS connections from anywhere (the normal ports for websites and SSL)." >> $1
  echo "-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT" >> $1
  echo "" >> $1
  echo "#  Allow SSH connections" >> $1
  echo "#" >> $1
  echo "#  The -dport number should be the same port number you set in sshd_config" >> $1
  echo "#" >> $1
  echo "-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT" >> $1
  echo "" >> $1
  echo "#  Allow shadowsocks connections" >> $1
  echo "# -A INPUT -p tcp -m state --state NEW --dport 753 -j ACCEPT" >> $1
  echo "" >> $1
  echo "#  Allow ping" >> $1
  echo "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT" >> $1
  echo "" >> $1
  echo "# allow outgoing DNS connections" >> $1
  echo "-A OUTPUT -p udp --dport 53 -j ACCEPT" >> $1
  echo "-A INPUT -p udp --sport 53 -j ACCEPT" >> $1
  echo "" >> $1
  echo "# Drop excessive RST packets to avoid smurf attacks" >> $1
  echo "-A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT" >> $1
  echo "" >> $1
  echo "-t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" >> $1
  echo "-t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -m multiport --sports 22,80,443 -j TCPMSS --set-mss 1440" >> $1
  echo "########################################################                                   ,753" >> $1
  echo "" >> $1
  echo "#  Log iptables denied calls" >> $1
  echo "-A INPUT -m limit --limit 5/min -j LOG --log-prefix \"iptables denied: \" --log-level 7" >> $1
  echo "" >> $1
  echo "#  Drop all other inbound - default deny unless explicitly allowed policy" >> $1
  echo "-A INPUT -j DROP" >> $1
  echo "# -A FORWARD -j DROP" >> $1
  echo "" >> $1
  echo "COMMIT" >> $1

}

ifconfig_for_china (){

iptables_firewall_rules /etc/iptables.firewall.rules

iptables-restore < /etc/iptables.firewall.rules

cat > /etc/network/if-pre-up.d/firewall <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
EOF

chmod +x /etc/network/if-pre-up.d/firewall

cat > /etc/sysctl.d/local.conf <<EOF
# All system parameters can be read or set by
# accessing special files in the /proc file system
# net.ipv4.tcp_moderate_rcvbuf = 1

# max open files
fs.file-max = 51200

# max read buffer
net.core.rmem_max = 253952

# max write buffer
net.core.wmem_max = 253952

# default read buffer
net.core.rmem_default = 126976

# default write buffer
net.core.wmem_default = 126976

# max processor input queue
net.core.netdev_max_backlog = 4096

# max backlog
net.core.somaxconn = 4096

# resist SYN flood attacks
net.ipv4.tcp_syncookies = 1

# reuse timewait sockets when safe
net.ipv4.tcp_tw_reuse = 1

# turn off fast timewait sockets recycling
net.ipv4.tcp_tw_recycle = 0

# short FIN timeout
net.ipv4.tcp_fin_timeout = 30

# short keepalive time
net.ipv4.tcp_keepalive_time = 1200

# outbound port range
net.ipv4.ip_local_port_range = 10000 65000

# max SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096

# max timewait sockets held by system simultaneously
net.ipv4.tcp_max_tw_buckets = 5000

# turn on TCP Fast Open on both client and server side
net.ipv4.tcp_fastopen = 3

# TCP receive buffer
net.ipv4.tcp_rmem = 4096 126976 253952

# TCP write buffer
net.ipv4.tcp_wmem = 20480 63488 253952

# Enable a fix for RFC1337 - time-wait assassination hazards in TCP
net.ipv4.tcp_rfc1337 = 1

# don't cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1

# turn off path MTU discovery
net.ipv4.tcp_mtu_probing = 1

# turn on tcp window scaling
net.ipv4.tcp_window_scaling = 1

# turn off tcp time stamps
net.ipv4.tcp_timestamps = 0

# turn on selective acknowledgement
net.ipv4.tcp_sack = 1

# Control use of Explicit Congestion Notification (ECN) by TCP
net.ipv4.tcp_ecn = 0

# for high-latency network
# net.ipv4.tcp_congestion_control = hybla

# for low-latency network, use cubic instead
# net.ipv4.tcp_congestion_control = htcp

EOF

# http://note.q2zy.com/shadowsocks%E9%85%8D%E7%BD%AE%E4%BC%98%E5%8C%96%E6%8A%98%E8%85%BE%E5%B0%8F%E8%AE%B0/
# https://www.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.27.tar.gz

# https://www.zxc.so/shadowsocks-ladder.html

# http://notes.xiamo.tk/2015-06-17-Digitalocean%E9%85%8D%E7%BD%AEshadowsocks%E6%9C%8D%E5%8A%A1%E5%99%A8-%E4%BC%98%E5%8C%96%E7%AC%94%E8%AE%B0.html

# budgetvm 4E8E4usE http://www.iptables.info/en/iptables-targets-and-jumps.html
# clamping_mss='\n# iptables -t nat -A POSTROUTING -j MASQUERADE\n# clamp mss\niptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s 169.254.0.0/16 -j TCPMSS --set-mss 1440\niptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s 172.16.0.0/12 -j TCPMSS --set-mss 1440\niptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s 192.168.0.0/16 -j TCPMSS --set-mss 1440\niptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -s 224.0.0.0/4 -j TCPMSS --set-mss 1440\niptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\nsysctl --system\nulimit -n 51200\n&'
# replace_second_occurrence 'exit 0' "$clamping_mss" /etc/rc.local

# review_file /etc/rc.local

# for vpn or mss clamping
# sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward = 1/" /etc/sysctl.conf

sysctl --system
# sysctl -p
sysctl net.ipv4.tcp_available_congestion_control
# chinaMTU_maker
chinaMTU_pre_maker eth1 1480

}

remove_file (){
  [ -f $1 ] && rm -f $1
}

remove_dir (){
  [ -d $1 ] && rm -rf $1
}

make_dir (){
  [ ! -d $1 ] && mkdir -p $1
}

review_file (){
  [ -f $1 ] && cp -f $1 /website
}

openvpn_patch_2_3_7 (){
  sed -i "s/\t\t\t     \&c->c2.from/&,\n\t\t\t     c->options.ce.xormethod,\n\t\t\t     c->options.ce.xormask,\n\t\t\t     c->options.ce.xormasklen/" src/openvpn/forward.c
  sed -i "s/\t\t\t\t      to_addr/&,\n\t\t\t\t      c->options.ce.xormethod,\n\t\t\t\t      c->options.ce.xormask,\n\t\t\t\t      c->options.ce.xormasklen/" src/openvpn/forward.c
  sed -i "s/  o->proto_force = -1;/&\n  o->ce.xormethod = 0;\n  o->ce.xormask = \"\\\\0\";\n  o->ce.xormasklen = 0;/" src/openvpn/options.c
  sed -i "s/  setenv_int_i (es, \"remote_port\", e->remote_port, i);/&\n  setenv_int_i (es, \"xormethod\", e->xormethod, i);\n  setenv_str_i (es, \"xormask\", e->xormask, i);\n  setenv_int_i (es, \"xormasklen\", e->xormasklen, i);/" src/openvpn/options.c
  sed -i "s/  SHOW_INT (connect_retry_max);/&\n  SHOW_INT (xormethod);\n  SHOW_STR (xormask);\n  SHOW_INT (xormasklen);/" src/openvpn/options.c
  replace_third_occurrence "      options->force_connection_list = true;" \
   "&\n    }\n  else if (streq (p[0], \"scramble\") \&\& p[1])\n    {\n      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);\n      if (streq (p[1], \"xormask\") \&\& p[2] \&\& (\!p[3]))\n	{\n	  options->ce.xormethod = 1;\n	  options->ce.xormask = p[2];\n	  options->ce.xormasklen = strlen(options->ce.xormask);\n	}\n      else if (streq (p[1], \"xorptrpos\") \&\& (\!p[2]))\n	{\n	  options->ce.xormethod = 2;\n	  options->ce.xormask = NULL;\n	  options->ce.xormasklen = 0;\n	}\n      else if (streq (p[1], \"reverse\") \&\& (\!p[2]))\n	{\n	  options->ce.xormethod = 3;\n	  options->ce.xormask = NULL;\n	  options->ce.xormasklen = 0;\n	}\n      else if (streq (p[1], \"obfuscate\") \&\& p[2] \&\& (\!p[3]))\n	{\n	  options->ce.xormethod = 4;\n	  options->ce.xormask = p[2];\n	  options->ce.xormasklen = strlen(options->ce.xormask);\n	}\n      else if (\!p[2])\n	{\n	  msg (M_WARN, \"WARNING: No recognized 'scramble' method specified; using 'scramble xormask \\\\\"%s\\\\\"'\", p[1]);\n	  options->ce.xormethod = 1;\n	  options->ce.xormask = p[1];\n	  options->ce.xormasklen = strlen(options->ce.xormask);\n	}\n      else\n	{\n	  msg (msglevel, \"No recognized 'scramble' method specified or extra parameters for 'scramble'\");\n	  goto err;\n	}" \
   src/openvpn/options.c

  sed -i "s/  bool connect_timeout_defined;/&\n  int xormethod;\n  const char \*xormask;\n  int xormasklen;/" src/openvpn/options.h
  sed -i "s/openvpn_connect (socket_descriptor_t sd,/buffer_mask (struct buffer \*buf, const char \*xormask, int xormasklen) {\n   int i;\n   uint8_t \*b;\n   if (  xormasklen > 0  ) {\n     for (i = 0, b = BPTR (buf); i < BLEN(buf); i++, b++) {\n        \*b = \*b \^ xormask[i % xormasklen];\n     }\n   }\n   return BLEN (buf);\n}\n\nint buffer_xorptrpos (struct buffer \*buf) {\n   int i;\n   uint8_t \*b;\n   for (i = 0, b = BPTR (buf); i < BLEN(buf); i++, b++) {\n     \*b = \*b \^ i+1;\n   }\n   return BLEN (buf);\n}\n\nint buffer_reverse (struct buffer \*buf) {\n\/\* This function has been rewritten for Tunnelblick. The buffer_reverse function at\n \* https:\/\/github.com\/clayface\/openvpn_xorpatch\n \* makes a copy of the buffer and it writes to the byte \*\*after\*\* the\n \* buffer contents, so if the buffer is full then it writes outside of the buffer.\n \* This rewritten version does neither.\n \*\n \* For interoperability, this rewritten version preserves the behavior of the original\n \* function: it does not modify the first character of the buffer. So it does not\n \* actually reverse the contents of the buffer. Instead, it changes 'abcde' to 'aedcb'.\n \* (Of course, the actual buffer contents are bytes, and not necessarily characters.)\n \*\/\n  int len = BLEN(buf);\n  if (  len > 2  ) {                           \/\* Leave '', 'a', and 'ab' alone \*\/\n    int i;\n    uint8_t \*b_start = BPTR (buf) + 1;	        \/\* point to first byte to swap \*\/\n    uint8_t \*b_end   = BPTR (buf) + (len - 1); \/\* point to last byte to swap \*\/\n    uint8_t tmp;\n    for (i = 0; i < (len-1)\/2; i++, b_start++, b_end--) {\n      tmp = \*b_start;\n      \*b_start = \*b_end;\n      \*b_end = tmp;\n    }\n  }\n  return len;\n}\n\nint\n&/" src/openvpn/socket.c

  sed -i "s/ \* Some Posix\/Win32 differences./\*\/\n\nint buffer_mask (struct buffer \*buf, const char \*xormask, int xormasklen);\nint buffer_xorptrpos (struct buffer \*buf);\nint buffer_reverse (struct buffer \*buf);\n\n\/\*\n&/" src/openvpn/socket.h
  sed -i "s/\t\t  struct link_socket_actual \*from/&,\n\t\t  int xormethod,\n\t\t  const char \*xormask,\n\t\t  int xormasklen/" src/openvpn/socket.h

  replace_first_occurrence "  if (proto_is_udp(sock->info.proto)) \/\* unified UDPv4 and UDPv6 \*\/" \
   "  int res;\n&" src/openvpn/socket.h

  sed -i "s/      int res;/\/\/&/" src/openvpn/socket.h
  sed -i "s/      return res;/\/\/&/" src/openvpn/socket.h
  sed -i "s/      return link_socket_read_tcp (sock, buf);/      res = link_socket_read_tcp (sock, buf);/" src/openvpn/socket.h

  replace_first_occurrence "      return -1; \/\* NOTREACHED \*\/" \
   "&\n    }\n  switch(xormethod)\n    {\n      case 1:\n       buffer_mask(buf, xormask, xormasklen);\n       break;\n      case 3:\n       buffer_reverse(buf);\n       break;\n      case 4:\n       buffer_mask(buf, xormask, xormasklen);\n       buffer_xorptrpos(buf);\n       buffer_reverse(buf);\n      case 2:\n       buffer_xorptrpos(buf);\n      case 0:\n       break;\n      default:\n       ASSERT (0);\n       return -1; \/\*\* NOTREACHED \*\*\/\n    }\n  return res;\n}\n\/\*" \
   src/openvpn/socket.h

  replace_third_occurrence "\t\t   struct link_socket_actual \*to" \
   "&,\n\t\t   int xormethod,\n\t\t   const char \*xormask,\n\t\t   int xormasklen" \
   src/openvpn/socket.h

  replace_second_occurrence "  if (proto_is_udp(sock->info.proto)) \/\* unified UDPv4 and UDPv6 \*\/" \
    "  switch(xormethod)\n    {\n      case 2:\n       buffer_xorptrpos(buf);\n       break;\n      case 3:\n       buffer_reverse(buf);\n       break;\n      case 4:\n       buffer_xorptrpos(buf);\n       buffer_reverse(buf);\n       buffer_xorptrpos(buf);\n      case 1:\n       buffer_mask(buf, xormask, xormasklen);\n      case 0:\n       break;\n      default:\n       ASSERT (0);\n       return -1; \/\*\* NOTREACHED \*\*\/\n    }\n&" \
    src/openvpn/socket.h

}

check_if_root() {
    if ! [ $(whoami) = "root" ]; then
            echo "ERROR: you must run this script as root!"
            exit 1
    fi

#    if [ $(id -u) != "0" ]; then
#        echo "Erreur : Cet utilisateur ne peut pas exécuter ce script, veuillez changer l'utilisateur en root avant de lancer le script"
#        exit 1
#    fi

}

usage() {

    echo "Usage: setup-generic-buildsystem.sh <oscodename>"
    echo
    echo "Parameter <oscodename> is:"
    echo
    echo "    trusty  (Ubuntu 14.04)"
    echo "    precise (Ubuntu 12.04)"
    echo "    quantal (Ubuntu 12.10)"
    echo
    echo "Example:"
    echo
    echo "   setup-generic-buildsystem.sh trusty"
    echo
    exit 1
}

# Patched .deb files fix a few serious issues:
#
# 1) On Ubuntu 12.04/12.10 the stock mingw version fails to build OpenVPN-GUI
# 2) On Ubuntu 12.04-14.04 the stock nsis version does not support long strings
#    required when extremely longs paths are used (Trac #465).
#

setup_generic_buildsystem_3_sh (){
# https://community.openvpn.net/openvpn/raw-attachment/wiki/SettingUpGenericBuildsystem/setup-generic-buildsystem.3.sh
# https://community.openvpn.net/openvpn/attachment/wiki/SettingUpGenericBuildsystem/setup-generic-buildsystem.3.sh
# Script to setup the environment for openvpn-build/generic and openvpn-build/windows-nsis

  BUILD_DEPS="mingw-w64 man2html dos2unix nsis unzip wget curl autoconf"
  OSSLSIGNCODE_DEPS="libssl-dev libcurl4-openssl-dev build-essential"
  OSSLSIGNCODE_URL="http://sourceforge.net/projects/osslsigncode/files/latest/download"
  OSSLSIGNCODE_PACKAGE="osslsigncode-latest.tar.gz"
  OPENVPN_BUILD_URL="https://github.com/OpenVPN/openvpn-build.git"
  PATCHED_DEBS_BASEURL="http://build.openvpn.net/downloads/packaging"

  if [ "$1" = "trusty" ]; then
      PATCHED_DEBS="nsis-common_2.46-101_all.deb nsis-doc_2.46-101_all.deb nsis-pluginapi_2.46-101_all.deb nsis_2.46-101_amd64.deb"
      GIT_PKG="git"
      GNUEABI_PKG="gcc-4.7-arm-linux-gnueabi"
  elif [ "$1" = "precise" ]; then
      PATCHED_DEBS="mingw-w64-dev_2.0.1-101_all.deb mingw-w64-tools_2.0.1-101_amd64.deb mingw-w64_2.0.1-101_all.deb nsis-common_2.46-101_all.deb nsis-doc_2.46-101_all.deb nsis-pluginapi_2.46-101_all.deb nsis_2.46-101_amd64.deb"
      GIT_PKG="git-core"
      GNUEABI_PKG="gcc-4.6-arm-linux-gnueabi"
  elif [ "$1" = "quantal" ]; then
      PATCHED_DEBS="mingw-w64-dev_2.0.3-101_all.deb mingw-w64-tools_2.0.3-101_amd64.deb mingw-w64_2.0.3-101_all.deb mingw-w64-i686-dev_2.0.3-101_all.deb mingw-w64-x86-64-dev_2.0.3-101_all.deb nsis-common_2.46-101_all.deb nsis-doc_2.46-101_all.deb nsis-pluginapi_2.46-101_all.deb nsis_2.46-101_amd64.deb"
      GIT_PKG="git-core"
      GNUEABI_PKG="gcc-4.6-arm-linux-gnueabi"
  else
      echo "ERROR: unknown oscodename"
      echo
      usage
  fi

# check_if_root

      apt_get_y_install $BUILD_DEPS $GIT_PKG rsync $GNUEABI_PKG $OSSLSIGNCODE_DEPS

  # osslsigncode is required for signing the binaries and installers

      if [[ -f /vagrant/patches/$OSSLSIGNCODE_PACKAGE ]]; then
        tar -zxf /vagrant/patches/$OSSLSIGNCODE_PACKAGE -C .
      else
        curl -L $OSSLSIGNCODE_URL > $OSSLSIGNCODE_PACKAGE
        cp -f $OSSLSIGNCODE_PACKAGE /vagrant/patches
        tar -zxf $OSSLSIGNCODE_PACKAGE
      fi
      cd osslsigncode-*
      ./configure >/dev/null 2>&1
      make >/dev/null 2>&1
      make install >/dev/null 2>&1
      cd ..

  if ! [ "$PATCHED_DEBS" = "" ]; then

        for DEB in $PATCHED_DEBS; do
            if ! [ -r $DEB ]; then
                if [[ -f /vagrant/patches/$DEB ]]; then
                  cp -f /vagrant/patches/$DEB ./
                else
                  curl -O $PATCHED_DEBS_BASEURL/$DEB
                  cp -f $DEB /vagrant/patches
                fi
            fi
        done
        dpkg -i $PATCHED_DEBS
  fi

      remove_dir openvpn-build
      if ! [ -d "openvpn-build" ]; then
          git clone $OPENVPN_BUILD_URL
      fi
}

build_scrambled_windows_openvpn_client (){
# https://scramblevpn.wordpress.com/2013/09/28/build-patched-windows-openvpn-client/

# If Ubuntu 14.04 trusty
setup_generic_buildsystem_3_sh $DISTRO
remove_apache2_completely

# to get patch
# cd openvpn-build/generic/patches
# wget -q https://raw.githubusercontent.com/clayface/openvpn_xorpatch/master/openvpn_xor.patch
# wget https://github.com/clayface/openvpn_xorpatch/archive/master.zip
# unzip master.zip
# cp -f openvpn_xorpatch-master/openvpn_xor.patch ./
# rm -rf master.zip openvpn_xorpatch-master/

# Patch not being applied automatically (why ?), so we apply patch long way

cd openvpn-build/windows-nsis

sed -i "s/\"\${WGET}\" \${WGET_OPTS} --directory-prefix=\${TMPDIR} \"\${EASY/if [ -f \/vagrant\/patches\/easy-rsa-\${EASY_RSA_VERSION}.tar.gz ]; then\n  if \! [ -d \${TMPDIR} ]; then\n    mkdir -p \${TMPDIR}\n  fi\n  cp -f \/vagrant\/patches\/easy-rsa-\${EASY_RSA_VERSION}.tar.gz \${TMPDIR}\nelse\n&/" build-complete
sed -i "s/\"\${WGET}\" \${WGET_OPTS} --directory-prefix=\${TMPDIR} \"\${TAP/fi\n\nif [ -f \/vagrant\/patches\/tap-windows-\${TAP_WINDOWS_INSTALLER_VERSION}.exe ]; then\n  if \! [ -d \${TMPDIR} ]; then\n    mkdir -p \${TMPDIR}\n  fi\n  cp -f \/vagrant\/patches\/tap-windows-\${TAP_WINDOWS_INSTALLER_VERSION}.exe \${TMPDIR}\nelse\n&/" build-complete
sed -i "s/die \"get tap-windows\"/&\nfi\n\n/" build-complete

[ $openvpn_version == '6' ] || \
 sed -i \
 "s/OPENVPN_VERSION=\"\${OPENVPN_VERSION:-2.3.6}\"/OPENVPN_VERSION=\"\${OPENVPN_VERSION:-2.3.$openvpn_version}\"/" \
 ../generic/build.vars

make_dir sources
cd sources
tar -xf /vagrant/patches/openvpn-2.3.$openvpn_version.tar.xz -C .
cd openvpn-2.3.$openvpn_version
openvpn_patch_2_3_7
cd ..
tar cfz openvpn-2.3.$openvpn_version.tar.gz openvpn-2.3.$openvpn_version
remove_dir openvpn-2.3.$openvpn_version

cp -f /vagrant/patches/lzo-2.08.tar.gz ./
cp -f /vagrant/patches/openssl-1.0.1j.tar.gz ./
cp -f /vagrant/patches/openvpn-gui-6.tar.gz ./
cp -f /vagrant/patches/pkcs11-helper-1.11.tar.bz2 ./
cp -f /vagrant/patches/tap-windows-9.21.1.zip ./

cd ..

# | grep -vi 'warning|error|critical'
./build-complete >/dev/null 2>&1

cd ../..
rsync -rqzh --exclude=.git --delete openvpn-build/ /website/openvpn-build/

echo "here you are..."
echo $(pwd)
echo "you know where you are..."

}

OpenVPN_obfuscation (){
# https://vpnchinaopenvz.wordpress.com/author/scramblevpn/
# https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.3.6txp/patches/02-tunnelblick-openvpn_xorpatch.diff
# https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.3.7txp/patches/02-tunnelblick-openvpn_xorpatch.diff
# https://tunnelblick.googlecode.com/svn-history/r3304/trunk/third_party/sources/openvpn/openvpn-2.3.6txp/patches/02-tunnelblick-openvpn_xorpatch.diff
# https://tunnelblick.googlecode.com/svn-history/r3328/trunk/third_party/sources/openvpn/openvpn-2.3.7txp/patches/02-tunnelblick-openvpn_xorpatch.diff
# https://tunnelblick.net/cOpenvpn_xorpatch.html#the-patch-as-modified-for-use-in-tunnelblick-for-openvpn-2.3.$openvpn_version
# https://www.digitalocean.com/community/tutorials/how-to-set-up-an-openvpn-server-on-ubuntu-14-04
# http://ixorthings.blogspot.jp/2015/07/howto-openvpn-obfuscation-with-xorpatch.html

apt_get_y_install build-essential libssl-dev liblzo2-dev libpam0g-dev git-core chkconfig

remove_file openvpn_xor.patch
remove_file openvpn-2.3.$openvpn_version.tar.xz
remove_dir openvpn-2.3.$openvpn_version

# wget -q http://kr.archive.ubuntu.com/ubuntu/pool/universe/e/easy-rsa/easy-rsa_2.2.2-1_all.deb
# dpkg -i easy-rsa_2.2.2-1_all.deb

# wget http://swupdate.openvpn.org/community/releases/openvpn-2.3.$openvpn_version.tar.xz
# http://build.openvpn.net/downloads/releases/openvpn-2.3.8.tar.gz

wget -q https://raw.githubusercontent.com/clayface/openvpn_xorpatch/master/openvpn_xor.patch
if [[ $openvpn_version == '7' ]]; then
  mv -f openvpn_xor.patch /vagrant/patches/
  cp -f /vagrant/patches/tunnelblick-patch-for-openvpn-2-3-7.patch ./openvpn_xor.patch
  dos2unix openvpn_xor.patch
elif [[ $openvpn_version == '6' ]]; then
  cp -f openvpn_xor.patch /vagrant/patches/
fi

# tar xvf openvpn-2.3.$openvpn_version.tar.xz
tar -xf /vagrant/patches/openvpn-2.3.$openvpn_version.tar.xz -C .

make_dir /etc/openvpn
cd openvpn-2.3.$openvpn_version

if [[ $openvpn_version == '7' ]]; then
  openvpn_patch_2_3_7
else
  patch -p1 < ../openvpn_xor.patch
fi

./configure --prefix=/usr >/dev/null 2>&1

# --enable-pkcs11 --enable-static=yes --enable-shared --enable-crypto --enable-ssl --disable-debug --disable-plugin-auth-pam --disable-dependency-tracking
make --enable-shared >/dev/null 2>&1
make install >/dev/null 2>&1

cd ..

# wget --no-check-cert https://www.dropbox.com/s/nz4dyons6tlsbr4/etcinitdopenvpn.sh -O /etc/init.d/openvpn
# wget --no-check-cert https://raw.githubusercontent.com/ThomasHabets/openvpn-debian/master/debian/openvpn.init.d -O /etc/init.d/openvpn

[ -f /etc/init.d/openvpn ] && update-rc.d -f openvpn remove
cp -f /vagrant/patches/etcinitdopenvpn.sh /etc/init.d/openvpn
dos2unix /etc/init.d/openvpn
# cp -f openvpn-2.3.$openvpn_version/distro/rpm/openvpn.init.d.suse /etc/init.d/openvpn
# sed -i 's/\$network/$network \$remote_fs \$syslog/' /etc/init.d/openvpn
# sed -i 's/# Default-Start:                3 5/# Should-Start:                 network-manager\n# Should-Stop:                  network-manager\n# Default-Start:                2 3 4 5/' /etc/init.d/openvpn
# sed -i 's/# Default-Stop:                 0 1 2 6/# Default-Stop:                 0 1 6/' /etc/init.d/openvpn
# sed -i 's/# Description:                  OpenVPN is a robust and highly flexible tunneling application that uses all of the encryption, authentication, and certification features of the OpenSSL library to securely tunnel IP networks over a single UDP port. /# Description:                  OpenVPN is a robust and highly flexible\n#                               tunneling application that uses all of\n#                               the encryption, authentication, and\n#                               certification features of the OpenSSL\n#                               library to securely tunnel IP\n#                               networks over a single UDP port./' /etc/init.d/openvpn
# sed -i 's/. /etc/rc.status/. lib/lsb/init-functions\n# &/' /etc/init.d/openvpn
sed -i 's/^# X-Start-Before:    \$x-display-manager gdm kdm xdm wdm ldm sdm nodm//' /etc/init.d/openvpn
sed -i 's/^# X-Interactive:     true//' /etc/init.d/openvpn
chmod +x /etc/init.d/openvpn

update-rc.d openvpn defaults
# update_rc_d openvpn '3 5' '0 1 2 6'
# Check startup script is correctly set
chkconfig --list | grep openvpn

# remove_file /website/forward.c
# remove_file /website/options.c
# remove_file /website/socket.c
# remove_file /website/options.h
# remove_file /website/socket.h

review_file openvpn-2.3.$openvpn_version/src/openvpn/forward.c
review_file openvpn-2.3.$openvpn_version/src/openvpn/options.c
review_file openvpn-2.3.$openvpn_version/src/openvpn/socket.c
review_file openvpn-2.3.$openvpn_version/src/openvpn/options.h
review_file openvpn-2.3.$openvpn_version/src/openvpn/socket.h
remove_file openvpn_xor.patch
remove_file openvpn-2.3.$openvpn_version.tar.xz

scramble_password='mylikeit'
server_port='5387'
server_IP_pool='10.73.59'
openvpn_server_IP_itsself='192.168.152.87'
internet_interface='eth1'
# venet0

cp -f openvpn-2.3.$openvpn_version/sample/sample-config-files/server.conf /etc/openvpn/
cp -f openvpn-2.3.$openvpn_version/sample/sample-config-files/openvpn-startup.sh /etc/openvpn/openvpn-startup
sed -i 's/^modprobe tun/# &/' /etc/openvpn/openvpn-startup
sed -i 's/^openvpn --cd \$dir --daemon --config vpn/# &/' /etc/openvpn/

# cat > /etc/openvpn/tun0.conf <<EOF
# dev tun0
# ifconfig $server_IP_pool.1 $server_IP_pool.2
# secret ~/serverside/easy-rsa/ta.key

# EOF

cp -f openvpn-2.3.$openvpn_version/sample/sample-config-files/openvpn-shutdown.sh /etc/openvpn/openvpn-shutdown

cat > /etc/openvpn/firewall.sh <<EOF
#!/bin/sh

# An OpenVPN-aware firewall.

# http://www.savjee.be/2014/04/Running-OpenVPN-on-a-cheap-RamNode-VPS/
# http://arashmilani.com/post?id=53

# OpenVPN (depending on the port you run OpenVPN)
iptables -A INPUT -i $internet_interface -m state --state NEW -p udp --dport $server_port -j ACCEPT

# Allow TUN interface connections to OpenVPN server
iptables -A INPUT -i tun+ -j ACCEPT

# Allow TUN interface connections to be forwarded through other interfaces
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o $internet_interface -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $internet_interface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# NAT the VPN client traffic to the internet
iptables -t nat -A POSTROUTING -s $server_IP_pool.0/24 -o $internet_interface -j MASQUERADE

# If your default iptables OUTPUT value is
# not ACCEPT, you will also need a line like:
iptables -A OUTPUT -o tun+ -j ACCEPT

EOF

chmod +x /etc/openvpn/openvpn-startup
chmod +x /etc/openvpn/openvpn-shutdown
chmod +x /etc/openvpn/firewall.sh
cp -f openvpn-2.3.$openvpn_version/sample/sample-config-files/client.conf /etc/openvpn/client.ovpn

scramble="# You need to put one of the following options in server.conf and client config\!\n#  - This simply reverses all the data in the packet.\n#    This is enough to get past the regular\n#    expression detection in both China and Iran.\n;scramble reverse\n\n#  - This performs a xor operation, utilizing\n#    the current position in the packet payload.\n;scramble xorptrpos\n\n#  - This method is more secure. It utilizes\n#    the 3 types of scrambling mentioned above.\n#    \"password\" is the string which you want to use.\nscramble obfuscate"
tun_mtu_desc="http:\/\/mdsh.com\/wiki\/jsp\/Wiki;jsessionid=0F6155DFDF36F18252CDD8D7A3B6CB2A?VPN:OpenVPN\n#   My OpenVPN server is on the end of an ADSL circuit. The most efficient size\n#   for MTU is 1454 bytes (see http:\/\/www.mynetwatchman.com\/kb\/adsl\/pppoemtu.htm).\n#   For a UDP OpenVPN tunnel there is a protocol overhead of 69 bytes per packet\n#   (41 bytes for OpenVPN and 28 bytes for UDP\/IP),\n#   although compression of the data stream may reduce that\n#   (see http:\/\/openvpn.net\/archive\/openvpn-users\/2004-11\/msg00649.html).\n#\n#   Therefore, to ensure no packet fragmentation and to try to maximise ADSL\n#   throughput, I set the MTU of UDP based tunnels to 1385 bytes. UDP\n#   fragmentation appears to break OpenVPN tunnel to a Tomato\n#   OpenLinksys device, and setting 'tun-mtu 1385' fixed that completely.\n#\n#   Similarly for a TCP OpenVPN tunnel there is a protocol overhead of 93 bytes\n#   per packet (41 bytes for OpenVPN and 52 bytes for TCP\/IP). Therefore\n#   I set the MTU of TCP based tunnels, as seen above, to 1361 bytes.\ntun-mtu 1411"

sed -i "s/port 1194/port $server_port/" /etc/openvpn/server.conf
sed -i "s/server 10.8.0.0 255.255.255.0/server $server_IP_pool.0 255.255.255.0/" /etc/openvpn/server.conf
sed -i 's/;push "redirect-gateway def1 bypass-dhcp"/push "redirect-gateway def1 bypass-dhcp"/' /etc/openvpn/server.conf
sed -i 's/;push "dhcp-option DNS 208.67.222.222"/push "dhcp-option DNS 208.67.222.222"/' /etc/openvpn/server.conf
sed -i 's/;push "dhcp-option DNS 208.67.220.220"/push "dhcp-option DNS 208.67.220.220"/' /etc/openvpn/server.conf
sed -i 's/;user nobody/user nobody/' /etc/openvpn/server.conf
sed -i 's/;group nobody/group nobody/' /etc/openvpn/server.conf
sed -i "s/# The maximum number of concurrently connected/\n# $tun_mtu_desc\n\n&/" /etc/openvpn/server.conf
sed -i "s/# Windows needs the TAP-Win32 adapter name/$scramble $scramble_password\n\n&/" /etc/openvpn/server.conf

sed -i 's/^;dev tap/dev tap/' /etc/openvpn/client.ovpn
sed -i 's/^dev tun/;dev tun/' /etc/openvpn/client.ovpn
sed -i "s/^remote my-server-1 1194/\nremote $openvpn_server_IP_itsself $server_port\n;&/" /etc/openvpn/client.ovpn
sed -i "s/# Keep trying indefinitely to resolve the/\n# $tun_mtu_desc\n\n&/" /etc/openvpn/client.ovpn
sed -i "s/# Windows needs the TAP-Win32 adapter name/$scramble $scramble_password\n\n&/" /etc/openvpn/client.ovpn

remove_dir openvpn-2.3.$openvpn_version

remove_dir serverside
remove_dir clientside

make_dir serverside/easy-rsa
make_dir clientside
cd clientside
remove_dir easy-rsa
git_clone OpenVPN easy-rsa
cd easy-rsa
# http://agiletesting.blogspot.jp/2015/01/setting-up-openvpn-server-inside-aws-vpc.html
# http://www.mydbapool.com/installing-configuring-openvpn-ubuntu-linux-5-minutes/
./build/build-dist.sh

tar xvzf ./EasyRSA-git-development.tgz
rm -f EasyRSA-git-development.tgz
cd EasyRSA-git-development

mv -f vars.example vars
sed -i 's/#set_var EASYRSA\t"\$PWD"/set_var EASYRSA\t"\$PWD"/' vars
sed -i 's/#set_var EASYRSA_OPENSSL\t"openssl"/set_var EASYRSA_OPENSSL\t"openssl"/' vars
sed -i 's/#set_var EASYRSA_PKI\t\t"\$EASYRSA\/pki"/set_var EASYRSA_PKI\t\t"\$EASYRSA\/pki"/' vars
sed -i 's/#set_var EASYRSA_DN\t"cn_only"/set_var EASYRSA_DN\t"org"/' vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"US"/' vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"California"/' vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"San Francisco"/' vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/' vars
sed -i 's/#set_var EASYRSA_REQ_EMAIL\t"me@example.net"/set_var EASYRSA_REQ_EMAIL\t"me@example.net"/' vars
sed -i 's/#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/' vars
sed -i 's/#set_var EASYRSA_KEY_SIZE\t2048/set_var EASYRSA_KEY_SIZE\t2048/' vars
sed -i 's/#set_var EASYRSA_ALGO\t\trsa/set_var EASYRSA_ALGO\t\trsa/' vars
sed -i 's/#set_var EASYRSA_CA_EXPIRE\t3650/set_var EASYRSA_CA_EXPIRE\t3650/' vars
sed -i 's/#set_var EASYRSA_CERT_EXPIRE\t3650/set_var EASYRSA_CERT_EXPIRE\t3650/' vars
sed -i 's/#set_var EASYRSA_SSL_CONF\t"\$EASYRSA\/openssl-1.0.cnf"/set_var EASYRSA_SSL_CONF\t"\$EASYRSA\/openssl-1.0.cnf"/' vars
sed -i 's/#set_var EASYRSA_BATCH\t\t""/set_var EASYRSA_BATCH\t\t"Yes"/' vars

cd ../..
rsync -rqzh --exclude=.git --delete easy-rsa/ ../serverside/easy-rsa/
cd easy-rsa/EasyRSA-git-development

./easyrsa init-pki
./easyrsa gen-req client1 nopass

cd ../../../serverside/easy-rsa/EasyRSA-git-development

./easyrsa init-pki
./easyrsa build-ca nopass
# ./easyrsa gen-req server nopass
# ./easyrsa sign-req server server
./easyrsa build-server-full server nopass
./easyrsa gen-dh >/dev/null 2>&1
openvpn --genkey --secret ../ta.key
./easyrsa import-req ../../../clientside/easy-rsa/EasyRSA-git-development/pki/reqs/client1.req client1
./easyrsa sign-req client client1

cd ../..

remove_dir /website/server-easy-rsa/.git
remove_dir /website/server-easy-rsa
remove_dir /website/client-easy-rsa/.git
remove_dir /website/client-easy-rsa

rsync -rqzh --exclude=.git --delete easy-rsa/ /website/server-easy-rsa/
cd ../clientside
rsync -rqzh --exclude=.git --delete easy-rsa/ /website/client-easy-rsa/
cd ..

# {ca.crt, server.crt, server.key, ta.key, dh2048.pem(or dh.pem)}

cp -f serverside/easy-rsa/EasyRSA-git-development/pki/ca.crt /etc/openvpn/
cp -f serverside/easy-rsa/EasyRSA-git-development/pki/issued/server.crt /etc/openvpn/
cp -f serverside/easy-rsa/EasyRSA-git-development/pki/private/server.key /etc/openvpn/
cp -f serverside/easy-rsa/ta.key /etc/openvpn/
cp -f serverside/easy-rsa/EasyRSA-git-development/pki/dh.pem /etc/openvpn/

cp -f serverside/easy-rsa/EasyRSA-git-development/pki/ca.crt clientside/
cp -f serverside/easy-rsa/EasyRSA-git-development/pki/issued/client1.crt clientside/
cp -f clientside/easy-rsa/EasyRSA-git-development/pki/private/client1.key clientside/
cp -f serverside/easy-rsa/ta.key clientside/

# chmod 600 /etc/openvpn/client.conf /etc/openvpn/ca.crt
# chmod 600 /etc/openvpn/client.crt /etc/openvpn/client.key

cur_dir=$(pwd)
cd /etc/openvpn
merge_server
cp -f client.ovpn $cur_dir/clientside/client1.ovpn
cd $cur_dir/clientside
merge_client client1
cd ..

cp -f clientside/client1.ovpn /website
cp -f /etc/init.d/openvpn /website

remove_dir /website/openvpn_settings

rsync -rqzh --delete /etc/openvpn/ /website/openvpn_settings/

service openvpn start

}

remove_apache2_completely (){
  service apache2 stop
  apt-get -y purge apache2 apache2-utils apache2.2-bin apache2-common
  apt-get -y autoremove
  whereis apache2
  rm -rf /etc/apache2
# insserv -r apache2
  update-rc.d -f apache2 remove
  rm -f /etc/init.d/apache2
}

imap_and_pop3 (){
  #Autoriser MySQL à écouter sur toutes les interfaces
  #Backup my.cnf
  cp /etc/mysql/my.cnf /etc/mysql/my.cnf.backup
  sed -i "s/bind-address\t\t= 127.0.0.1/# &/" /etc/mysql/my.cnf
  service mysql restart

  #Suppression et reconfiguration des certificats SSL
  cd /etc/courier
  rm -f imapd.pem
  rm -f pop3d.pem
  sed -i "s/CN=localhost/CN=${HOSTNAMEFQDN}/" imapd.cnf
  sed -i "s/CN=localhost/CN=${HOSTNAMEFQDN}/" pop3d.cnf
  mkimapdcert >/dev/null 2>&1
  mkpop3dcert >/dev/null 2>&1
  service courier-imap-ssl restart
  service courier-pop-ssl restart
}

debian_install_basic (){

#Def hostname && FQDN
sed -i "s/${serverIP}.*/${serverIP} ${HOSTNAMEFQDN} ${HOSTNAMESHORT}/" /etc/hosts
echo "$HOSTNAMESHORT" > /etc/hostname
/etc/init.d/hostname.sh start >/dev/null 2>&1

#MAJ serveur && installation des outils
#Sauvegarde fichier sources.list
cp /etc/apt/sources.list /etc/apt/sources.list.backup
# http://linuxconfig.org/debian-apt-get-wheezy-sources-list
cat > /etc/apt/sources.list <<EOF

deb http://ftp.$1.debian.org/debian/ $DISTRO main contrib non-free
deb-src http://ftp.$1.debian.org/debian/ $DISTRO main contrib non-free

deb http://security.debian.org/ $DISTRO/updates main contrib non-free
deb-src http://security.debian.org/ $DISTRO/updates main contrib non-free

# $DISTRO-updates, previously known as 'volatile'
deb http://ftp.$1.debian.org/debian/ $DISTRO-updates main contrib non-free
deb-src http://ftp.$1.debian.org/debian/ $DISTRO-updates main contrib non-free

# DotDeb
deb http://packages.dotdeb.org $DISTRO all
deb-src http://packages.dotdeb.org $DISTRO all
EOF

apt-get -y remove openssl
apt-get -y purge openssl
apt-get -y autoremove

# wget http://www.dotdeb.org/dotdeb.gpg
# cat dotdeb.gpg | apt-key add -
wget --quiet http://www.dotdeb.org/dotdeb.gpg -O- | apt-key add -

apt-get update
apt-get -y upgrade
apt_get_y_install rsync build-essential

openssl_version='openssl-1.0.2d'
wget http://openssl.org/source/$openssl_version.tar.gz -q
tar -xf $openssl_version.tar.gz
rm -f $openssl_version.tar.gz
cd $openssl_version
sed -i 's# libcrypto.a##;s# libssl.a##' Makefile

./config --prefix=/usr shared zlib-dynamic > /dev/null 2>&1

make > /dev/null 2>&1
make install > /dev/null 2>&1
cd ..

apt_get_y_install vim-nox dnsutils unzip

} #fin fct debian_install_basic

mysql_server_answer (){
  if [[ -z $mysql_server_answer_done ]]; then
    if [[ "$sql_server" == 'MariaDB' ]]; then
      theversion=10.0
    else
      theversion=5.5
    fi
    echo "$sql_server-server-$theversion mysql-server/root_password password $mysql_pass" | debconf-set-selections
    echo "$sql_server-server-$theversion mysql-server/root_password_again password $mysql_pass" | debconf-set-selections
  else
    mysql_server_answer_done=yes
  fi
}

postfix_answer (){
  if [[ -z $postfix_answer_done ]]; then
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string $HOSTNAMEFQDN" | debconf-set-selections
  else
    postfix_answer_done=yes
  fi
}

courier_answer (){
  if [[ -z $courier_answer_done ]]; then
    echo "courier-base courier-base/webadmin-configmode boolean false" | debconf-set-selections
    echo "courier-ssl courier-ssl/certnotice note" | debconf-set-selections
  else
    courier_answer_done=yes
  fi
}

debian_install_DashNTP (){

echo "dash dash/sh boolean false" | debconf-set-selections
dpkg-reconfigure -f noninteractive dash > /dev/null 2>&1

#Synchronisationn de l'horloge du système
apt_get_y_install ntp ntpdate

} #fin fct debian_install_DashNTP

debian_install_MySQLCourier (){

#Installation de Postfix, Courier, Saslauthd, MySQL, phpMyAdmin, rkhunter, binutils
mysql_server_answer
postfix_answer
courier_answer
apt_get_y_install postfix postfix-mysql postfix-doc mysql-client mysql-server courier-authdaemon courier-authlib-mysql courier-pop courier-pop-ssl courier-imap courier-imap-ssl libsasl2-2 libsasl2-modules libsasl2-modules-sql sasl2-bin libpam-mysql openssl courier-maildrop getmail4 rkhunter binutils sudo

imap_and_pop3

} #fin fct debian_install_MySQLCourier

debian_install_MariaDBCourier (){

#Instalaltion prop python
apt_get_y_install python-software-properties

add_apt_repository_mariadb

#Installation Postfix, Courier, Saslauthd, MySQL, phpMyAdmin, rkhunter, binutils
mysql_server_answer
postfix_answer
courier_answer

apt_get_y_install postfix postfix-mysql postfix-doc mariadb-server mariadb-client courier-authdaemon courier-authlib-mysql courier-pop courier-pop-ssl courier-imap courier-imap-ssl libsasl2-2 libsasl2-modules libsasl2-modules-sql sasl2-bin libpam-mysql openssl courier-maildrop getmail4 rkhunter binutils sudo

imap_and_pop3

} #fin fct debian_install_MariaDBCourier

debian_install_MySQLDovecot (){

#Installation Postfix, Dovecot, Saslauthd, MySQL, phpMyAdmin, rkhunter, binutils
mysql_server_answer
postfix_answer

apt_get_y_install postfix postfix-mysql postfix-doc mysql-client mysql-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve sudo

#Décommenter les lignes utiles dans postfix
#Backup master.cf
cp /etc/postfix/master.cf /etc/postfix/master.cf.backup
sed -i 's|#submission inet n       -       -       -       -       smtpd|submission inet n       -       -       -       -       smtpd|' /etc/postfix/master.cf
sed -i 's|#  -o syslog_name=postfix/submission|  -o syslog_name=postfix/submission|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_tls_security_level=encrypt|  -o smtpd_tls_security_level=encrypt|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject|  -o smtpd_client_restrictions=permit_sasl_authenticated,reject|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#smtps     inet  n       -       -       -       -       smtpd|smtps     inet  n       -       -       -       -       smtpd|' /etc/postfix/master.cf
sed -i 's|#  -o syslog_name=postfix/smtps|  -o syslog_name=postfix/smtps|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_tls_wrappermode=yes|  -o smtpd_tls_wrappermode=yes|' /etc/postfix/master.cf

#Autoriser MySQL à écouter sur toutes les interfaces
#Backup my.cnf
cp /etc/mysql/my.cnf /etc/mysql/my.cnf.backup
sed -i "s/bind-address\t\t= 127.0.0.1/# &/" /etc/mysql/my.cnf

service postfix restart
service mysql restart

} #fin fct debian_install_MySQLDovecot

debian_install_MariaDBDovecot (){

#Instalaltion prop python
apt_get_y_install python-software-properties

add_apt_repository_mariadb

#Installation Postfix, Dovecot, Saslauthd, MySQL, phpMyAdmin, rkhunter, binutils
mysql_server_answer
postfix_answer

apt_get_y_install postfix postfix-mysql postfix-doc mariadb-server mariadb-client openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve sudo

#Décommenter les lignes utiles dans postfix
#Backup master.cf
cp /etc/postfix/master.cf /etc/postfix/master.cf.backup
sed -i 's|#submission inet n       -       -       -       -       smtpd|submission inet n       -       -       -       -       smtpd|' /etc/postfix/master.cf
sed -i 's|#  -o syslog_name=postfix/submission|  -o syslog_name=postfix/submission|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_tls_security_level=encrypt|  -o smtpd_tls_security_level=encrypt|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject|  -o smtpd_client_restrictions=permit_sasl_authenticated,reject|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_sasl_auth_enable=yes|  -o smtpd_sasl_auth_enable=yes|' /etc/postfix/master.cf
sed -i 's|#smtps     inet  n       -       -       -       -       smtpd|smtps     inet  n       -       -       -       -       smtpd|' /etc/postfix/master.cf
sed -i 's|#  -o syslog_name=postfix/smtps|  -o syslog_name=postfix/smtps|' /etc/postfix/master.cf
sed -i 's|#  -o smtpd_tls_wrappermode=yes|  -o smtpd_tls_wrappermode=yes|' /etc/postfix/master.cf

#Autoriser MySQL à écouter sur toutes les interfaces
#Backup my.cnf
cp /etc/mysql/my.cnf /etc/mysql/my.cnf.backup
sed -i "s/bind-address\t\t= 127.0.0.1/# &/" /etc/mysql/my.cnf

service postfix restart
service mysql restart

} #fin function debian_install_MariaDBDovecot

debian_install_ANTI_Virus (){

#Installation Amavisd-new, SpamAssassin, And Clamav
apt_get_y_install amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl

service spamassassin stop
insserv -rf spamassassin

} #fin fct debian_install_ANTI_Virus

debian_install_Apache (){

echo "============================================================================="
echo "Vous devrez saisir quelques informations durant l'installation de phpmyadmin."
echo "Choisissez <No> à la question configure using dbconfig-common"
echo "Veuillez saisir les informations lorsqu'elles vous seront demandées."
echo "============================================================================="
echo "Appuyez sur Entrée pour continuer..."
# read DUMMY

#Installation Apache2, PHP5, phpMyAdmin, FCGI, suExec, Pear, And mcrypt

echo 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2' | debconf-set-selections

apt_get_y_install apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-gd php5-mysqlnd php5-imap phpmyadmin php5-cli php5-cgi libapache2-mod-fcgid apache2-suexec php-pear php-auth php5-mcrypt mcrypt php5-imagick imagemagick libapache2-mod-suphp libruby libapache2-mod-ruby libapache2-mod-python php5-curl php5-intl php5-memcache php5-memcached php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl memcached

a2enmod suexec rewrite ssl actions include
a2enmod dav_fs dav auth_digest

#Fix Ming
cp /etc/php5/cli/conf.d/ming.ini /etc/php5/cli/conf.d/ming.ini.backup
rm /etc/php5/cli/conf.d/ming.ini
cat > /etc/php5/cli/conf.d/ming.ini <<EOF
extension=ming.so
EOF

#Fix SuPHP
cp /etc/apache2/mods-available/suphp.conf /etc/apache2/mods-available/suphp.conf.backup
rm /etc/apache2/mods-available/suphp.conf
cat > /etc/apache2/mods-available/suphp.conf <<EOF
<IfModule mod_suphp.c>
    #<FilesMatch "\.ph(p3?|tml)$">
    #    SetHandler application/x-httpd-suphp
    #</FilesMatch>
        AddType application/x-httpd-suphp .php .php3 .php4 .php5 .phtml
        suPHP_AddHandler application/x-httpd-suphp

    <Directory />
        suPHP_Engine on
    </Directory>

    # By default, disable suPHP for debian packaged web applications as files
    # are owned by root and cannot be executed by suPHP because of min_uid.
    <Directory /usr/share>
        suPHP_Engine off
    </Directory>

# # Use a specific php config file (a dir which contains a php.ini file)
#       suPHP_ConfigPath /etc/php5/cgi/suphp/
# # Tells mod_suphp NOT to handle requests with the type <mime-type>.
#       suPHP_RemoveHandler <mime-type>
</IfModule>
EOF

#Activation de la prise en charge Ruby
sed -i 's|application/x-ruby|#application/x-ruby|' /etc/mime.types

#Installation de XCache
apt_get_y_install php5-xcache

#Restart Apache
service apache2 restart

} #fin fct debian_install_Apache

debian_install_NginX (){

#Install NginX, PHP5, phpMyAdmin, FCGI, suExec, Pear, And mcrypt

add-apt-repository "deb http://nginx.org/packages/mainline/debian/ $DISTRO nginx"
echo "deb-src http://nginx.org/packages/mainline/debian/ $DISTRO nginx" >> /etc/apt/sources.list

wget --quiet http://nginx.org/keys/nginx_signing.key -O- | apt-key add -

apt-get update

apt_get_y_install nginx-extras
remove_apache2_completely
service nginx start

apt_get_y_install php5-fpm
apt_get_y_install php5-mysqlnd php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-memcached php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl memcached
apt_get_y_install php-apc
#Configuration PHP
apt_get_y_install fcgiwrap

echo 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect none' | debconf-set-selections
# https://github.com/servisys/ispconfig_setup/blob/master/distros/debian7/install_webserver.sh
# - DISABLED DUE TO A BUG IN DBCONFIG
# echo 'phpmyadmin phpmyadmin/dbconfig-install boolean false' | debconf-set-selections
# echo 'dbconfig-common dbconfig-common/dbconfig-install boolean false' | debconf-set-selections

echo 'phpmyadmin phpmyadmin/dbconfig-install boolean true' | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password $mysql_pass" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password $phpmyadmin_app_password" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password $phpmyadmin_app_password" | debconf-set-selections

echo "============================================================================="
echo "Vous devrez saisir quelques informations durant l'installation de phpmyadmin."
echo "Choisissez <No> à la question : configure using dbconfig-common ?"
echo "Veuillez saisir les informations lorsqu'elles vous seront demandées."
echo "============================================================================="
echo "Appuyez sur Entrée pour continuer..."
# read DUMMY

apt_get_y_install phpmyadmin

#Supprimer Apache2 pour NginX
remove_apache2_completely
service nginx start

#Fix Ming
cp /etc/php5/cli/conf.d/ming.ini /etc/php5/cli/conf.d/ming.ini.backup
rm /etc/php5/cli/conf.d/ming.ini
cat > /etc/php5/cli/conf.d/ming.ini <<EOF
extension=ming.so
EOF

service php5-fpm restart

} #fin fct debian_install_NginX

debian_install_Mailman (){

echo "================================================================================================"
echo "Vous devrez saisir quelques informations durant l'installation."
echo "Sélectionnez votre langue puis validez par OK quand vous serez informé que la liste de site est absente"
echo "Vous devrez également renseigner l'Email du responsable de la liste ainsi que le mot de passe pour la liste"
echo "Veuillez saisir les informations lorsqu'elles vous seront demandées."
echo "============================================================================="
echo "Appuyez sur Entrée pour continuer..."
# read DUMMY

#Installation Mailman
apt_get_y_install mailman
newlist mailman

mv /etc/aliases /etc/aliases.backup

cat > /etc/aliases.mailman <<EOF
mailman:              "|/var/lib/mailman/mail/mailman post mailman"
mailman-admin:        "|/var/lib/mailman/mail/mailman admin mailman"
mailman-bounces:      "|/var/lib/mailman/mail/mailman bounces mailman"
mailman-confirm:      "|/var/lib/mailman/mail/mailman confirm mailman"
mailman-join:         "|/var/lib/mailman/mail/mailman join mailman"
mailman-leave:        "|/var/lib/mailman/mail/mailman leave mailman"
mailman-owner:        "|/var/lib/mailman/mail/mailman owner mailman"
mailman-request:      "|/var/lib/mailman/mail/mailman request mailman"
mailman-subscribe:    "|/var/lib/mailman/mail/mailman subscribe mailman"
mailman-unsubscribe:  "|/var/lib/mailman/mail/mailman unsubscribe mailman"
EOF

cat /etc/aliases.backup /etc/aliases.mailman > /etc/aliases
newaliases
service postfix restart
    if [ $web_server == "Apache" ]; then
        ln -s /etc/mailman/apache.conf /etc/apache2/conf.d/mailman.conf
        service apache2 restart
    fi
service mailman start

} #fin fct debian_install_Mailman

debian_install_PureFTPD (){
#Install PureFTPd
apt_get_y_install pure-ftpd-common pure-ftpd-mysql

#Setting up Pure-Ftpd
sed -i 's/VIRTUALCHROOT=false/VIRTUALCHROOT=true/' /etc/default/pure-ftpd-common
echo 1 > /etc/pure-ftpd/conf/TLS
mkdir -p /etc/ssl/private/

openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -subj "/C=/ST=/L=/O=/CN=$(hostname -f)" -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
chmod 600 /etc/ssl/private/pure-ftpd.pem
service pure-ftpd-mysql restart

} #fin fct debian_install_Ftpd

debian_install_Quota (){

#Editing FStab
cp /etc/fstab /etc/fstab.backup
sed -i "s/errors=remount-ro/errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0/" /etc/fstab

#Setting up Quota
apt_get_y_install quota quotatool
mount -o remount /
quotacheck -avugm
quotaon -avug

} #fin fct debian_install_Quota

debian_install_Bind (){
#Install BIND DNS Server
apt_get_y_install bind9 dnsutils

} #fin fct debian_install_Bind

debian_install_Stats (){

#Install Vlogger, Webalizer, And AWstats
apt_get_y_install vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl

sed -i "s/*/10 * * * * www-data/#*/10 * * * * www-data/" /etc/cron.d/awstats
sed -i "s/10 03 * * * www-data/#10 03 * * * www-data/" /etc/cron.d/awstats

}

debian_install_Jailkit (){
#Install Jailkit
apt_get_y_install build-essential autoconf automake1.9 libtool flex bison debhelper binutils-gold

cd /tmp
wget http://olivier.sessink.nl/jailkit/jailkit-2.16.tar.gz
tar xvfz jailkit-2.16.tar.gz
cd jailkit-2.16
./debian/rules binary
cd ..
dpkg -i jailkit_2.16-1_*.deb
rm -rf jailkit-2.16*

} #fin fct debian_install_Jailkit

debian_install_Fail2BanCourier (){
#Install fail2ban
apt_get_y_install fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[pureftpd]
enabled  = true
port     = ftp
filter   = pureftpd
logpath  = /var/log/syslog
maxretry = 3

[sasl]
enabled  = true
port     = smtp
filter   = sasl
logpath  = /var/log/mail.log
maxretry = 5

[courierpop3]
enabled  = true
port     = pop3
filter   = courierpop3
logpath  = /var/log/mail.log
maxretry = 5

[courierpop3s]
enabled  = true
port     = pop3s
filter   = courierpop3s
logpath  = /var/log/mail.log
maxretry = 5

[courierimap]
enabled  = true
port     = imap2
filter   = courierimap
logpath  = /var/log/mail.log
maxretry = 5

[courierimaps]
enabled  = true
port     = imaps
filter   = courierimaps
logpath  = /var/log/mail.log
maxretry = 5
EOF
} #fin fct debian_install_Fail2banCourier

debian_install_Fail2BanDovecot() {
#Install fail2ban
apt_get_y_install fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[pureftpd]
enabled  = true
port     = ftp
filter   = pureftpd
logpath  = /var/log/syslog
maxretry = 3

[dovecot-pop3imap]
enabled = true
filter = dovecot-pop3imap
action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
logpath = /var/log/mail.log
maxretry = 5

[sasl]
enabled  = true
port     = smtp
filter   = sasl
logpath  = /var/log/mail.log
maxretry = 3
EOF

} #fin fct debian_install_Fail2banDovecot

debian_install_Fail2BanRulesCourier() {

cat > /etc/fail2ban/filter.d/pureftpd.conf <<EOF
[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/courierpop3.conf <<EOF
[Definition]
failregex = pop3d: LOGIN FAILED.*ip=\[.*:<HOST>\]
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/courierpop3s.conf <<EOF
[Definition]
failregex = pop3d-ssl: LOGIN FAILED.*ip=\[.*:<HOST>\]
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/courierimap.conf <<EOF
[Definition]
failregex = imapd: LOGIN FAILED.*ip=\[.*:<HOST>\]
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/courierimaps.conf <<EOF
[Definition]
failregex = imapd-ssl: LOGIN FAILED.*ip=\[.*:<HOST>\]
ignoreregex =
EOF

service fail2ban restart

} #fin fct debian_install_Fail2banRulesCourier

debian_install_Fail2BanRulesDovecot() {

cat > /etc/fail2ban/filter.d/pureftpd.conf <<EOF
[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/dovecot-pop3imap.conf <<EOF
[Definition]
failregex = (?: pop3-login|imap-login): .*(?:Authentication failure|Aborted login \(auth failed|Aborted login \(tried to use disabled|Disconnected \(auth failed|Aborted login \(\d+ authentication attempts).*rip=(?P<host>\S*),.*
ignoreregex =
EOF

service fail2ban restart

} #fin fct debian_install_Fail2banRulesDovecot

debian_install_SquirrelMail (){

echo "==========================================================================================="
echo "Au prompt, choisissez D! Ensuite sélectionnez le serveur de mail que vous avez choisi : ($mail_server),"
echo "Validez en appuyant sur Entrée."
echo "Sélectionnez S, puis validez sur Entrée."
echo "Sélectionnez Q, puis validez sur entrée"
echo "==========================================================================================="
echo "Appuyez sur Entrée pour continuer..."
# read DUMMY
#Installation SquirrelMail
apt_get_y_install squirrelmail
# squirrelmail-configure

if [ $web_server == "Apache" ]; then
mv /etc/squirrelmail/apache.conf /etc/squirrelmail/apache.conf.backup
cat > /etc/squirrelmail/apache.conf <<EOF
Alias /squirrelmail /usr/share/squirrelmail
Alias /webmail /usr/share/squirrelmail

<Directory /usr/share/squirrelmail>
  Options FollowSymLinks
  <IfModule mod_php5.c>
    AddType application/x-httpd-php .php
    php_flag magic_quotes_gpc Off
    php_flag track_vars On
    php_admin_flag allow_url_fopen Off
    php_value include_path .
    php_admin_value upload_tmp_dir /var/lib/squirrelmail/tmp
    php_admin_value open_basedir /usr/share/squirrelmail:/etc/squirrelmail:/var/lib/squirrelmail:/etc/hostname:/etc/mailname
    php_flag register_globals off
  </IfModule>
  <IfModule mod_dir.c>
    DirectoryIndex index.php
  </IfModule>

  # access to configtest is limited by default to prevent information leak
  <Files configtest.php>
    order deny,allow
    deny from all
    allow from 127.0.0.1
  </Files>
</Directory>

# users will prefer a simple URL like http://webmail.example.com
#<VirtualHost 1.2.3.4>
#  DocumentRoot /usr/share/squirrelmail
#  ServerName webmail.example.com
#</VirtualHost>

# redirect to https when available (thanks omen@descolada.dartmouth.edu)
#
#  Note: There are multiple ways to do this, and which one is suitable for
#  your site's configuration depends. Consult the apache documentation if
#  you're unsure, as this example might not work everywhere.
#
#<IfModule mod_rewrite.c>
#  <IfModule mod_ssl.c>
#    <Location /squirrelmail>
#      RewriteEngine on
#      RewriteCond %{HTTPS} !^on$ [NC]
#      RewriteRule . https://%{HTTP_HOST}%{REQUEST_URI}  [L]
#    </Location>
#  </IfModule>
#</IfModule>
EOF
mkdir /var/lib/squirrelmail/tmp
chown www-data /var/lib/squirrelmail/tmp
ln -s /etc/squirrelmail/apache.conf /etc/apache2/conf.d/squirrelmail.conf
service apache2 reload
else
  remove_apache2_completely
fi
} #fin fct debian_install_SquirellMail

install_ISPConfig (){
#Installation ISPConfig 3
cd /tmp
wget http://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz -q
tar -xf ISPConfig-3-stable.tar.gz
rm -f ISPConfig-3-stable.tar.gz
cd ispconfig3_install/install/

ispconfig_user='ispconfig'
ispconfig_password='afStEratXBsgatRtsa42CadwhQ'

echo "Create INI file"
if [ $web_server == 'NginX' ]; then
  remove_apache2_completely
  treat_apache=n
  treat_http_server=nginx
else
  treat_apache=y
  treat_http_server=apache
fi

if [ $jailkit == "Yes" ]; then
  treat_jailkit=y
else
  treat_jailkit=n
fi

  touch autoinstall.ini
  echo "[install]" > autoinstall.ini
  echo "language=en" >> autoinstall.ini
  echo "install_mode=standard" >> autoinstall.ini
  echo "hostname=$HOSTNAMEFQDN" >> autoinstall.ini
  echo "mysql_hostname=localhost" >> autoinstall.ini
  echo "mysql_root_user=root" >> autoinstall.ini
  echo "mysql_root_password=$mysql_pass" >> autoinstall.ini
  echo "mysql_database=dbispconfig" >> autoinstall.ini
  echo "mysql_charset=utf8" >> autoinstall.ini
  echo "http_server=$treat_http_server" >> autoinstall.ini
  echo "ispconfig_port=443" >> autoinstall.ini
  echo "ispconfig_use_ssl=y" >> autoinstall.ini
  echo "" >> autoinstall.ini
  echo "[ssl_cert]" >> autoinstall.ini
  echo "ssl_cert_country=IT" >> autoinstall.ini
  echo "ssl_cert_state=Italy" >> autoinstall.ini
  echo "ssl_cert_locality=Udine" >> autoinstall.ini
  echo "ssl_cert_organisation=Servisys di Temporini Matteo" >> autoinstall.ini
  echo "ssl_cert_organisation_unit=IT department" >> autoinstall.ini
  echo "ssl_cert_common_name=$HOSTNAMEFQDN" >> autoinstall.ini
  echo "" >> autoinstall.ini
  echo "[expert]" >> autoinstall.ini
  echo "mysql_ispconfig_user=$ispconfig_user" >> autoinstall.ini
  echo "mysql_ispconfig_password=$ispconfig_password" >> autoinstall.ini
  echo "join_multiserver_setup=n" >> autoinstall.ini
  echo "mysql_master_hostname=$HOSTNAMESHORT" >> autoinstall.ini
  echo "mysql_master_root_user=root" >> autoinstall.ini
  echo "mysql_master_root_password=ispconfig" >> autoinstall.ini
  echo "mysql_master_database=dbispconfig" >> autoinstall.ini
  echo "configure_mail=y" >> autoinstall.ini
  echo "configure_jailkit=$treat_jailkit" >> autoinstall.ini
  echo "configure_ftp=y" >> autoinstall.ini
  echo "configure_dns=y" >> autoinstall.ini
  echo "configure_apache=$treat_apache" >> autoinstall.ini
  echo "configure_nginx=n" >> autoinstall.ini
  echo "configure_firewall=y" >> autoinstall.ini
  echo "install_ispconfig_web_interface=y" >> autoinstall.ini
  echo "" >> autoinstall.ini
  echo "[update]" >> autoinstall.ini
  echo "do_backup=yes" >> autoinstall.ini
  echo "mysql_root_password=$mysql_pass" >> autoinstall.ini
  echo "mysql_master_hostname=$HOSTNAMESHORT" >> autoinstall.ini
  echo "mysql_master_root_user=root" >> autoinstall.ini
  echo "mysql_master_root_password=ispconfig" >> autoinstall.ini
  echo "mysql_master_database=dbispconfig" >> autoinstall.ini
  echo "reconfigure_permissions_in_master_database=no" >> autoinstall.ini
  echo "reconfigure_services=yes" >> autoinstall.ini
  echo "ispconfig_port=443" >> autoinstall.ini
  echo "create_new_ispconfig_ssl_cert=no" >> autoinstall.ini
  echo "reconfigure_crontab=yes" >> autoinstall.ini
  php -q install.php --autoinstall=autoinstall.ini > /dev/null 2>&1

rm -rf ispconfig3_install/

} #fin fct debian_install_Fail2banCourier

# http://www.team-aaz.com/forum/les-tutoriels/script-installation-serveur-vps-complet-en-1-seule-ligne-t11693.html
# Check if user is root

check_if_root

back_title="Installation automatisée de serveur"
flag_word='okgoodbyexitZEROthisisreplacesecondoccurrence'

#what_distro=$(lsb_release -c | awk {'print $2'})
DISTRO=$(lsb_release -sc)
openvpn_version='7'

swap_creation

#FCT EXEC START#

if [[ ${13} == 'china' ]]; then
  echo "change mtu to 1480 for china servers..."
  ifconfig_for_china
else

if [ -f /etc/debian_version ]; then
  questions $1 $2 $3 $4 $5 $6 $7 $8 $9 ${10} ${11}
if [[ ${13} == 'openvpnserver' ]]; then
  add_apt_repository_ubuntu
  OpenVPN_obfuscation
elif [[ ${13} == 'openvpn' ]]; then
  add_apt_repository_ubuntu
  build_scrambled_windows_openvpn_client
else
  debian_install_basic ${12}
  debian_install_DashNTP
  if [[ $sql_server == "MySQL" && $mail_server == "Courier" ]]; then
        debian_install_MySQLCourier
  fi
  if [[ $sql_server == "MySQL" && $mail_server ==  "Dovecot" ]]; then
      debian_install_MySQLDovecot
   fi
  if [[ $sql_server == "MariaDB" && $mail_server == "Courier" ]]; then
      debian_install_MariaDBCourier
  fi
  if [[ $sql_server == "MariaDB" && $mail_server ==  "Dovecot" ]]; then
      debian_install_MariaDBDovecot
  fi
   debian_install_ANTI_Virus
   if [ $web_server == "Apache" ]; then
      debian_install_Apache
   # fi
   # if [ $web_server == "NginX" ]; then
 else
      debian_install_NginX
   fi
   if [ $mailman == "Yes" ]; then
      debian_install_Mailman
   fi
   debian_install_PureFTPD
   if [ $quota == "Yes" ]; then
      debian_install_Quota
   fi
   debian_install_Bind
  debian_install_Stats
  if [ $jailkit == "Yes" ]; then
      debian_install_Jailkit
   fi
   if [ $mail_server == "Courier" ]; then
      debian_install_Fail2BanCourier
      debian_install_Fail2BanRulesCourier
    else
    if [ $mail_server == "Dovecot" ]; then
      debian_install_Fail2BanDovecot
      debian_install_Fail2BanRulesDovecot
    fi
  fi
  debian_install_SquirrelMail
  install_ISPConfig
fi
else echo "Erreur : Version de Linux non supportée."
fi

#FCT EXEC FIN#
fi
