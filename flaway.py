def startup_service__(name, dir1, filename):
    #Create the Startup Service Certificate
    cert = f"""
    [Unit]
    Description={name}
    After=multi-user.target

    [Service]
    Type=simple
    ExecStart=/usr/bin/python3 {dir1}/{filename}.py
    StandardInput=tty-force

    [Install]
    WantedBy=multi-user.target
                  """
    #Try to Import & change your PWD
    try:
        from os import chdir
    except ImportError:
        print(f"[!] Configuration Error")
        exit(1)
    try:
        chdir('/etc/systemd/system/')
    except FileNotFoundError:
        print(f"[!] Could Not Locate systemd")
        exit(1)
    #Done Changed to /etc/systemd/
    filename = f"{filename}.service"
    with open(filename, 'w+') as fp1:
        fp1.write(cert)
    #Restart your Network Daemon
    check_output('sudo systemctl daemon-reload', shell=True)
    srtv1 = f"sudo systemctl enable {filename}"
    srtv2 = f"sudo systemctl start {filename}"
    #Enable & start your Service @ reboot
    check_output(srtv1, shell=True)
    check_output(srtv2, shell=True)
    filename = filename.split('.')
    filename = fl1[0]
    print(f"Created {filename} as a startup service")



def antivirus_software__(filename):
    #attempt to install Antivirus Software
    try:
        from os import chdir, mkdir
    except ImportError:
        print("[!] Configuration Error")
        exit(1)
    #only proceed if Directory is valid 
    while True:
        filelocations = input("LOCATION: ")
        try:
            mkdir(filelocations)
            chdir(filelocations)
        except FileNotFoundError:
            print(f"[!] Could not change PWD to {file_pointer}")
            continue
        break
    #This is the code to the antivirus Software :)
    menu2 = r'''
    from subprocess import check_output
    from time import sleep
    from os import name
    from struct import unpack
    from socket import AF_INET, inet_pton
    from random import randint
    from threading import Thread
    if name == 'nt':
        print("This tool is not supported with windows")
        exit(1)
    
    blacklist = []
    
    def verfiy_on_whitelist(item):
        """IP addresses in whitelist will never logged """
        if len(item) <= 1:
            return 1
        with open('whitelist.txt', 'r') as fp1:
            content2 = fp1.readlines()
        for line in content2:
            if item in line:
                print(f"{item} is whitelisted")
                return 0
        print(f"{item} is blacklisted")
        blacklist.append(item)
        return 1
    
    def sanitizer(test):
        try:
            t1 = test.split('   ')
            z   = t1[4].split(' ')
            k = z[1].split(':')
            ip1 = k[0]
            o = t1[6].split(':')
            ip2 = o[0]
        except:
            return None
        try:
            if len(ip1) >= 2:
                if lookup(ip1) == False:
                    verfiy_on_whitelist(ip1)
            if len(ip2) >= 2:
                if lookup(ip2) == False:
                    verfiy_on_whitelist(ip2)
        except:
            pass
    
    
    def lookup(ip):
        """this function checks weather or not the ip adress submitted is private"""
        f = unpack('!I',inet_pton(AF_INET,ip))[0]
        private = (
            [ 2130706432, 4278190080 ],
            [ 3232235520, 4294901760 ],
            [ 2886729728, 4293918720 ],
            [ 167772160,  4278190080 ],
        ) 
        for net in private:
            if (f & net[1]) == net[0]:
                return True
        return False
    record = []
    def logger():
        import datetime
        """every 30 seconds Any foreign IP adress that have connected
        to the machine will be loggged in the records List."""
        while True:
            if len(blacklist) != 0:
                sleep(30)
                id = f"{randint(1,9)}{randint(1,9)}{randint(1,9)}{randint(1,9)}{randint(1,9)}{randint(1,9)}"
                history = blacklist.copy()
                for ip in history:
                    if ip not in record:
                        record.append(ip)
                po = datetime.datetime.now()
                report = f"""[time={po.strftime("%I:%M:%S %p")}][date={po.strftime("%d/%m/%Y")}] [id={id}] ~ {str(record)}\n"""
                with open('report.txt', 'a') as file_pointer:
                    file_pointer.write(report)
                print("[Created Report]")
                blacklist.clear()
    
    def main():
        th = Thread(target=logger)
        th.start()
        while True:
            sleep(5)
            try:
                content = check_output('netstat -nputw', shell=True)
            except:
                check_output('apt-get install net-tools -y', shell=True)
                exit(1)
            content = str(content)
            content = content.split('\\n')
            for i in content:
                sanitizer(i)
    main()
    '''
    #create a copy of the antivirus Software
    with open(filename, 'w+') as file_pointer:
        file_pointer.write(menu2)
    return filelocations

def check_for_update__():
    try:
        from subprocess import check_output
    except ImportError:
        print("[!] Something Went Wrong :")
        exit(1)
    try: #update & upgrade your Operating System
        status = check_output('apt-get update -y', shell=True)
        status = check_output('apt-get upgrade -y', shell=True)
    except:
        print("[!] Something Went Wrong!")
        print(status)
    print("[Done]")

def reconfigure_secure_shell__(PORT):
    #make sure PORT is a valid Integer
    try:
        PORT = int(PORT)
    except ValueError:
        exit(1)
    #make sure the port is not to high
    if PORT >=  65536:
        exit(1)
    try:
        from subprocess import call
        from os import chdir, getuid
    except ImportError:
        exit(1)
    #Make sure you have the correct file permissions
    if getuid() != 0:
        print("[!] This configurations required Root!")
    else:
        #change your PORT 
        try:
            chdir('/etc/ssh')
        except:
            print("Please Install SSHD on your OS")
            exit(1)
        with open('sshd_config', 'r') as file_pointer1:
            container1 = file_pointer1.readlines()
            for lines in container1:
                if "#Port 22" in lines:
                    num = container1.index(lines)
                    #to whatever YOUR PORT # IS 
                    configure_port = f"Port {PORT}\n"
                    container1[num] = configure_port
    #attempt to remove SSHD_CONFIG & then Write it back
    call('rm -rf /etc/ssh/sshd_config', shell=True)
    with open('sshd_config', 'w+') as file_pointer2:
        for line in container1:
            file_pointer2.write(line)
    print(f"[!] Commited Change SSH port is ({PORT})")

def firewall__setup__():
    try:
        from subprocess import check_output
        from os import getuid
    except ImportError:
        exit(1)
    #check if this script is running with a PID(0)
    if getuid() != 0:
        print("[!] This configurations Require root")
    else:
        # Netfilter persistent is an opensource linux firewall protection
        print("[!] Attempting to install Network Filter")
        try:
            status = check_output("apt-get install iptables-persistent netfilter-persistent -y",shell=True)
            status = check_output("netfilter-persistent start",shell=True)
        except: # if something goes wrong print the exit code
            print(status)
        print("[+] Done")
        print("[!] Run(netfilter-persistent stop/restart) to change this at anytime")



# secure port is configured through a VPN Firewall mirrored on
#  Credit < https://hackmd.io/@teraswitch/BkBFpgAnU >
def secure__Ports__():
    from subprocess import call
    z_list1 = [
        """iptables -P INPUT ACCEPT""",
        """sudo iptables -P INPUT ACCEPT""",
        """sudo iptables -P FORWARD ACCEPT""",
        """sudo iptables -P OUTPUT ACCEPT""",
        """sudo iptables -N AS0_ACCEPT""",
        """sudo iptables -N AS0_IN""",
        """sudo iptables -N AS0_IN_NAT""",
        """sudo iptables -N AS0_IN_POST""",
        """sudo iptables -N AS0_IN_PRE""",
        """sudo iptables -N AS0_IN_ROUTE""",
        """sudo iptables -N AS0_OUT""",
        """sudo iptables -N AS0_OUT_LOCAL""",
        """sudo iptables -N AS0_OUT_POST""",
        """sudo iptables -N AS0_OUT_S2C""",
        """sudo iptables -N AS0_WEBACCEPT""",
        """sudo iptables -N f2b-sshd""",
        """sudo iptables -N flood""",
        """sudo iptables -N http-flood""",
        """sudo iptables -N port-scanning""",
        """sudo iptables -N syn-flood""",
        """sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT""",
        """sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 15 --connlimit-mask 32 --connlimit-saddr -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP""",
        """sudo iptables -A INPUT -p udp -m udp --dport 3074 -j ACCEPT""",
        """sudo iptables -A INPUT -p udp -m udp --dport 3075 -j ACCEPT""",
        """sudo iptables -A INPUT -m recent --rcheck --seconds 604800 --name portscan --mask 255.255.255.255 --rsource -j DROP""",
        """sudo iptables -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource""",
        """sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j AS0_ACCEPT""",
        """sudo iptables -A INPUT -i lo -j AS0_ACCEPT""",
        """sudo iptables -A INPUT -m mark --mark 0x2000000/0x2000000 -j AS0_IN_PRE""",
        """sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j AS0_WEBACCEPT""",
        """sudo iptables -A INPUT -s 127.0.0.1/32 -j ACCEPT""",
        """sudo iptables -A INPUT -s 172.27.224.1/32 -j ACCEPT""",
        """sudo iptables -A INPUT -s 51.222.27.82 -j ACCEPT""",
        """sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP""",
        """sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT""",
        """sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --dport 943 -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --dport 62627 -j DROP""",
        """sudo iptables -A INPUT -s 10.0.0.0/8 -j DROP""",
        """sudo iptables -A INPUT -s 169.254.0.0/16 -j DROP""",
        """sudo iptables -A INPUT -s 172.16.0.0/12 -j DROP""",
        """sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP""",
        """sudo iptables -A INPUT -s 224.0.0.0/4 -j DROP""",
        """sudo iptables -A INPUT -d 224.0.0.0/4 -j DROP""",
        """sudo iptables -A INPUT -s 240.0.0.0/5 -j DROP""",
        """sudo iptables -A INPUT -d 240.0.0.0/5 -j DROP""",
        """sudo iptables -A INPUT -s 0.0.0.0/8 -j DROP""",
        """sudo iptables -A INPUT -d 0.0.0.0/8 -j DROP""",
        """sudo iptables -A INPUT -d 239.255.255.0/24 -j DROP""",
        """sudo iptables -A INPUT -d 255.255.255.255/32 -j DROP""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT""",
        """sudo iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT""",
        """sudo iptables -A FORWARD -m recent --rcheck --seconds 604800 --name portscan --mask 255.255.255.255 --rsource -j DROP""",
        """sudo iptables -A FORWARD -m recent --remove --name portscan --mask 255.255.255.255 --rsource""",
        """sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j AS0_ACCEPT""",
        """sudo iptables -A FORWARD -m mark --mark 0x2000000/0x2000000 -j AS0_IN_PRE""",
        """sudo iptables -A FORWARD -o as0t+ -j AS0_OUT_S2C""",
        """sudo iptables -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec -j ACCEPT""",
        """sudo iptables -A FORWARD -p udp -m limit --limit 1/sec -j ACCEPT""",
        """sudo iptables -A FORWARD -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT""",
        """sudo iptables -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec -j ACCEPT""",
        """sudo iptables -A OUTPUT ! -s 127.181.42.17/32 ! -d 127.138.213.242/32 -p icmp -m icmp --icmp-type 3/3 -m connmark ! --mark 0x53a7de36 -j DROP""",
        """sudo iptables -A OUTPUT ! -s 127.17.79.83/32 ! -d 127.95.130.90/32 -p tcp -m tcp --sport 61001:65535 --tcp-flags RST RST -m connmark ! --mark 0x7bc1a1f4 -j DROP""",
        """sudo iptables -A OUTPUT -o as0t+ -j AS0_OUT_LOCAL""",
        """sudo iptables -A AS0_ACCEPT -j ACCEPT""",
        """sudo iptables -A AS0_IN -d 172.27.224.1/32 -j ACCEPT""",
        """sudo iptables -A AS0_IN -j AS0_IN_POST""",
        """sudo iptables -A AS0_IN_NAT -j MARK --set-xmark 0x8000000/0x8000000""",
        """sudo iptables -A AS0_IN_NAT -j ACCEPT""",
        """sudo iptables -A AS0_IN_POST -o as0t+ -j AS0_OUT""",
        """sudo iptables -A AS0_IN_POST -j DROP""",
        """sudo iptables -A AS0_IN_PRE -d 169.254.0.0/32 -j AS0_IN""",
        """sudo iptables -A AS0_IN_PRE -d 192.168.0.0/32 -j AS0_IN""",
        """sudo iptables -A AS0_IN_PRE -d 172.16.0.0/32 -j AS0_IN""",
        """sudo iptables -A AS0_IN_PRE -d 10.0.0.0/32 -j AS0_IN""",
        """sudo iptables -A AS0_IN_PRE -j ACCEPT""",
        """sudo iptables -A AS0_IN_ROUTE -j MARK --set-xmark 0x4000000/0x4000000""",
        """sudo iptables -A AS0_IN_ROUTE -j ACCEPT""",
        """sudo iptables -A AS0_OUT -j AS0_OUT_POST""",
        """sudo iptables -A AS0_OUT_LOCAL -p icmp -m icmp --icmp-type 5 -j DROP""",
        """sudo iptables -A AS0_OUT_LOCAL -j ACCEPT""",
        """sudo iptables -A AS0_OUT_POST -m mark --mark 0x2000000/0x2000000 -j ACCEPT""",
        """sudo iptables -A AS0_OUT_POST -j DROP""",
        """sudo iptables -A AS0_OUT_S2C -j AS0_OUT""",
        """sudo iptables -A AS0_WEBACCEPT -j ACCEPT""",
        """sudo iptables -A f2b-sshd -j RETURN""",
        """sudo iptables -A f2b-sshd -j RETURN""",
        """sudo iptables -A flood -j DROP""",
        """sudo iptables -A http-flood -j DROP""",
        """sudo iptables -A port-scanning -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec --limit-burst 2 -j RETURN""",
        """sudo iptables -A port-scanning -j DROP""",
        """sudo iptables -A syn-flood -m limit --limit 1/sec --limit-burst 4 -j RETURN""",
        """sudo iptables -A syn-flood -j DROP""",
        """sudo iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN""",
        """sudo iptables -A port-scanning -j DROP""",
        """sudo iptables -A syn-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -A syn-flood -j LOG --log-prefix "SYN flood: " """,
        """sudo iptables -A syn-flood -j DROP""",
        """sudo iptables -A INPUT -i lo -p udp --destination-port 123 -j DROP""",
        """sudo iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP""",
        """sudo iptables -N ntp-flood""",
        """sudo iptables -A ntp-flood -m limit --limit 15/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -A udp-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N FIN-flood""",
        """sudo iptables -A FIN-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N RST-flood""",
        """sudo iptables -A RST-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N PSH-flood""",
        """sudo iptables -A PSH-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N ACK-flood""",
        """sudo iptables -A ACK-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N STD-flood""",
        """sudo iptables -A STD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N HOLD-flood""",
        """sudo iptables -A HOLD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N JUNK-flood""",
        """sudo iptables -A JUNK-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N CNC-flood""",
        """sudo iptables -A CNC-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N ARD-flood""",
        """sudo iptables -A ARD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -N CHARGEN-flood""",
        """sudo iptables -A CHARGEN-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -A INPUT -p udp --source-port 19:19 -m state --state ESTABLISHED -j DROP""",
        """sudo iptables -A INPUT -p tcp --source-port 19:19 -m state --state ESTABLISHED -j DROP""",
        """sudo iptables -N ldap-flood""",
        """sudo iptables -A ldap-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """sudo iptables -A INPUT -p udp --source-port 389:389 -m state --state ESTABLISHED -j DROP""",
        """sudo iptables -A INPUT -p tcp --source-port 389:389 -m state --state ESTABLISHED -j DROP""",
        """sudo iptables -A INPUT -p tcp --dport 33333 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p tcp --dport 33333 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p udp --dport 33333 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p udp --dport 33333 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p udp --dport 80 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p udp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p tcp --dport 62627 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p tcp --dport 62627 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """sudo iptables -A INPUT -p udp --dport 62627 -i eth0 -m state --state NEW -m recent --set""",
        """sudo iptables -A INPUT -p udp --dport 62627 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -P FORWARD ACCEPT""",
        """iptables -P OUTPUT ACCEPT""",
        """iptables -N AS0_ACCEPT""",
        """iptables -N AS0_IN""",
        """iptables -N AS0_IN_NAT""",
        """iptables -N AS0_IN_POST""",
        """iptables -N AS0_IN_PRE""",
        """iptables -N AS0_IN_ROUTE""",
        """iptables -N AS0_OUT""",
        """iptables -N AS0_OUT_LOCAL""",
        """iptables -N AS0_OUT_POST""",
        """iptables -N AS0_OUT_S2C""",
        """iptables -N AS0_WEBACCEPT""",
        """iptables -N f2b-sshd""",
        """iptables -N flood""",
        """iptables -N http-flood""",
        """iptables -N port-scanning""",
        """iptables -N syn-flood""",
        """iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT""",
        """iptables -A INPUT -m conntrack --ctstate INVALID -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 15 --connlimit-mask 32 --connlimit-saddr -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP""",
        """iptables -A INPUT -p udp -m udp --dport 3074 -j ACCEPT""",
        """iptables -A INPUT -p udp -m udp --dport 3075 -j ACCEPT""",
        """iptables -A INPUT -m recent --rcheck --seconds 604800 --name portscan --mask 255.255.255.255 --rsource -j DROP""",
        """iptables -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource""",
        """iptables -A INPUT -m state --state RELATED,ESTABLISHED -j AS0_ACCEPT""",
        """iptables -A INPUT -i lo -j AS0_ACCEPT""",
        """iptables -A INPUT -m mark --mark 0x2000000/0x2000000 -j AS0_IN_PRE""",
        """iptables -A INPUT -d 195.58.39.146 -p udp -m state --state NEW -m udp --dport 9982 -j AS0_ACCEPT""",
        """iptables -A INPUT -m state --state RELATED,ESTABLISHED -j AS0_WEBACCEPT""",
        """iptables -A INPUT -s 127.0.0.1/32 -j ACCEPT""",
        """iptables -A INPUT -s 172.27.224.1/32 -j ACCEPT""",
        """iptables -A INPUT -s 51.222.27.82 -j ACCEPT""",
        """iptables -A INPUT -m conntrack --ctstate INVALID -j DROP""",
        """iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT""",
        """iptables -A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --dport 943 -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --dport 62627 -j DROP""",
        """iptables -A INPUT -s 10.0.0.0/8 -j DROP""",
        """iptables -A INPUT -s 169.254.0.0/16 -j DROP""",
        """iptables -A INPUT -s 172.16.0.0/12 -j DROP""",
        """iptables -A INPUT -s 127.0.0.0/8 -j DROP""",
        """iptables -A INPUT -s 224.0.0.0/4 -j DROP""",
        """iptables -A INPUT -d 224.0.0.0/4 -j DROP""",
        """iptables -A INPUT -s 240.0.0.0/5 -j DROP""",
        """iptables -A INPUT -d 240.0.0.0/5 -j DROP""",
        """iptables -A INPUT -s 0.0.0.0/8 -j DROP""",
        """iptables -A INPUT -d 0.0.0.0/8 -j DROP""",
        """iptables -A INPUT -d 239.255.255.0/24 -j DROP""",
        """iptables -A INPUT -d 255.255.255.255/32 -j DROP""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT""",
        """iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT""",
        """iptables -A FORWARD -m recent --rcheck --seconds 604800 --name portscan --mask 255.255.255.255 --rsource -j DROP""",
        """iptables -A FORWARD -m recent --remove --name portscan --mask 255.255.255.255 --rsource""",
        """iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j AS0_ACCEPT""",
        """iptables -A FORWARD -m mark --mark 0x2000000/0x2000000 -j AS0_IN_PRE""",
        """iptables -A FORWARD -o as0t+ -j AS0_OUT_S2C""",
        """iptables -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec -j ACCEPT""",
        """iptables -A FORWARD -p udp -m limit --limit 1/sec -j ACCEPT""",
        """iptables -A FORWARD -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT""",
        """iptables -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec -j ACCEPT""",
        """iptables -A OUTPUT ! -s 127.181.42.17/32 ! -d 127.138.213.242/32 -p icmp -m icmp --icmp-type 3/3 -m connmark ! --mark 0x53a7de36 -j DROP""",
        """iptables -A OUTPUT ! -s 127.17.79.83/32 ! -d 127.95.130.90/32 -p tcp -m tcp --sport 61001:65535 --tcp-flags RST RST -m connmark ! --mark 0x7bc1a1f4 -j DROP""",
        """iptables -A OUTPUT -o as0t+ -j AS0_OUT_LOCAL""",
        """iptables -A AS0_ACCEPT -j ACCEPT""",
        """iptables -A AS0_IN -d 172.27.224.1/32 -j ACCEPT""",
        """iptables -A AS0_IN -j AS0_IN_POST""",
        """iptables -A AS0_IN_NAT -j MARK --set-xmark 0x8000000/0x8000000""",
        """iptables -A AS0_IN_NAT -j ACCEPT""",
        """iptables -A AS0_IN_POST -o as0t+ -j AS0_OUT""",
        """iptables -A AS0_IN_POST -j DROP""",
        """iptables -A AS0_IN_PRE -d 169.254.0.0/32 -j AS0_IN""",
        """iptables -A AS0_IN_PRE -d 192.168.0.0/32 -j AS0_IN""",
        """iptables -A AS0_IN_PRE -d 172.16.0.0/32 -j AS0_IN""",
        """iptables -A AS0_IN_PRE -d 10.0.0.0/32 -j AS0_IN""",
        """iptables -A AS0_IN_PRE -j ACCEPT""",
        """iptables -A AS0_IN_ROUTE -j MARK --set-xmark 0x4000000/0x4000000""",
        """iptables -A AS0_IN_ROUTE -j ACCEPT""",
        """iptables -A AS0_OUT -j AS0_OUT_POST""",
        """iptables -A AS0_OUT_LOCAL -p icmp -m icmp --icmp-type 5 -j DROP""",
        """iptables -A AS0_OUT_LOCAL -j ACCEPT""",
        """iptables -A AS0_OUT_POST -m mark --mark 0x2000000/0x2000000 -j ACCEPT""",
        """iptables -A AS0_OUT_POST -j DROP""",
        """iptables -A AS0_OUT_S2C -j AS0_OUT""",
        """iptables -A AS0_WEBACCEPT -j ACCEPT""",
        """iptables -A f2b-sshd -j RETURN""",
        """iptables -A f2b-sshd -j RETURN""",
        """iptables -A flood -j DROP""",
        """iptables -A http-flood -j DROP""",
        """iptables -A port-scanning -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec --limit-burst 2 -j RETURN""",
        """iptables -A port-scanning -j DROP""",
        """iptables -A syn-flood -m limit --limit 1/sec --limit-burst 4 -j RETURN""",
        """iptables -A syn-flood -j DROP""",
        """iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN""",
        """iptables -A port-scanning -j DROP""",
        """iptables -A syn-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -A syn-flood -j LOG --log-prefix "SYN flood: " """,
        """iptables -A syn-flood -j DROP""",
        """iptables -A INPUT -i lo -p udp --destination-port 123 -j DROP""",
        """iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP""",
        """iptables -N ntp-flood""",
        """iptables -A ntp-flood -m limit --limit 15/sec --limit-burst 15 -j RETURN""",
        """iptables -A udp-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N FIN-flood""",
        """iptables -A FIN-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N RST-flood""",
        """iptables -A RST-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N PSH-flood""",
        """iptables -A PSH-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N ACK-flood""",
        """iptables -A ACK-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N STD-flood""",
        """iptables -A STD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N HOLD-flood""",
        """iptables -A HOLD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N JUNK-flood""",
        """iptables -A JUNK-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N CNC-flood""",
        """iptables -A CNC-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N ARD-flood""",
        """iptables -A ARD-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -N CHARGEN-flood""",
        """iptables -A CHARGEN-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -A INPUT -p udp --source-port 19:19 -m state --state ESTABLISHED -j DROP""",
        """iptables -A INPUT -p tcp --source-port 19:19 -m state --state ESTABLISHED -j DROP""",
        """iptables -N ldap-flood""",
        """iptables -A ldap-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN""",
        """iptables -A INPUT -p udp --source-port 389:389 -m state --state ESTABLISHED -j DROP""",
        """iptables -A INPUT -p tcp --source-port 389:389 -m state --state ESTABLISHED -j DROP""",
        """iptables -A INPUT -p tcp --dport 1194 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 1194 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 1194 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 1194 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p tcp --dport 33333 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 33333 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 33333 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 33333 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 80 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p tcp --dport 62627 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p tcp --dport 62627 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -A INPUT -p udp --dport 62627 -i eth0 -m state --state NEW -m recent --set""",
        """iptables -A INPUT -p udp --dport 62627 -i eth0 -m state --state NEW -m recent --update --seconds 150 --hitcount 10 -j DROP""",
        """iptables -N UDPATTACK""",
        """iptables -N DNSFLOOD""",
        """iptables -N TCPFLOOD""",
        """iptables -N SYNFLOOD""",
        """iptables -N ACKFLOOD""",
        """iptables -N STDFLOOD""",
        """iptables -N udp-flood""",
        """iptables -N synack-flood""",
        """iptables -A INPUT -p udp -m hashlimit --hashlimit-name UDPATTACK --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p udp -m hashlimit --hashlimit-name DNSFLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p tcp -m hashlimit --hashlimit-name TCPFLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p tcp -m hashlimit --hashlimit-name SYNFLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p tcp -m hashlimit --hashlimit-name ACKFLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p udp -m hashlimit --hashlimit-name STDFLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p udp -m hashlimit --hashlimit-name udp-flood --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
        """iptables -A INPUT -p udp -m hashlimit --hashlimit-name synack-flood --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 5/minute --hashlimit-burst 2 --hashlimit-htable-expire 30000 -j DROP""",
    ]
    print("Securing your servers ports...\nThis might take a while!")
    for item in z_list1:
        call(item, shell=True)
    print("[!] Done")



def block__port__scanner__():
    from subprocess import call
    z_list1 = [
        """iptables -A INPUT -p udp -m udp --dport 56550:56600 -j DROP""",
        """iptables -A INPUT -p udp -s 66.70.214.169 --dport 56559 -j DROP""",
        """iptables -A INPUT -p icmp -s 66.70.214.169 -j DROP""",
        """iptables -A INPUT -p udp -s 66.70.214.169 --dport 56560 -j DROP""",
        """iptables -A INPUT -p udp -s 66.70.214.169 --dport 56500:56599 -j DROP""",
        """iptables -A INPUT -p udp -s 66.70.214.169 --dport 56559 -j DROP""",
        """iptables -A INPUT -p udp -s 47.90.210.55/30 --dport 55600:55700 -j DROP""",
        """iptables -A INPUT -p udp -s 185.40.20.149/30 --dport 55600:55700 -j DROP""",
        """iptables -A INPUT -p udp -s 188.17.147.227/30 --sport 55900:56000 -j DROP""",
        """iptables -A INPUT -p udp -s 47.90.210.55/30 --sport 59300:59400 -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|b9 41 02 9e cb 41 5d 18 7c 2a 22 57 44 16 8c 34|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|ce ff ed 0e 12 49 c9 e2 15 1d 31 1b 4f 92 5c 92|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|5b d6 0f 55 51 ea ed 03 26 28 77 b7 52 a7 e4 47|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|61 c5 69 75 88 23 c9 7d af 4a f5 2a 4d 53 24 55|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|de cb fb 6d b7 f3 5d 4e b0 85 ab 76 41 98 1c bb|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|d3 ea c5 3c de 5c a9 78 29 d8 99 99 2c 75 cc 78|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|40 20 c7 e4 fd 5d ad fa 1a 42 bf 95 0f e9 34 8e|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|25 6f 01 63 15 f5 6a d3 84 c5 1d 69 ea f6 55 fc|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|82 d6 73 bb 24 26 de 05 65 5f b3 14 bd 9b 2d c1|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|57 54 1e eb 2b ee 0a 8f be 12 82 98 88 d7 bd df|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|a4 eb 00 f2 2a 4f ee 70 8f dd 88 f4 4b ac 05 54|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|6a 9a 1a d2 21 48 8a aa d8 bf c6 27 06 18 05 22|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|a7 60 6c 8a 10 d8 de 3b 99 ba 3c 33 ba 1d bd 48|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|5c 3f f6 19 f7 01 ea 25 d2 cd ea 16 65 ba 2d c5|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|89 35 b8 81 d6 c2 ae 67 83 f7 d0 d2 08 ee 55 9b|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|2e 44 b2 c0 ae 1a 2b 00 ad 3a ee 66 a3 bb 36 c9|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|4b 6b e4 d8 7d 0b 5f f2 4e 94 44 d1 36 20 ce 4e|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|e0 a9 4f c8 44 93 4b 3c 67 07 d3 15 c1 1c 1e 2c|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|ed 00 f1 8f 03 b4 ef dd f8 92 99 31 44 b1 26 61|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|73 6f cb 2f ba 6d 4b d7 01 34 97 24 bf dd e6 ef|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|70 f5 dd a7 69 bd 5f 28 82 ef cd f0 33 a2 5e d5|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|e5 94 27 f6 10 a6 2b d2 7b c2 3b 93 9e ff 8e 12|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|d2 4a a9 1e af 27 af d4 ec ac e1 0f 01 f3 76 a8|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|37 19 63 1d 47 3f ec 2d d6 af bf 63 5c 80 17 96|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|43 d1 e7 eb d9 33 04 08 5e cf d5 8e af a5 6f db|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65500 --match string --algo kmp --hex-string '|04 1c 0f f2 40 00 6f 11 0b 0a 2f 5a d2 37 a7 72|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|fa 16 3e c9 4f 58 46 16 25 83 cf 0c 08 00 45 00|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|fa 16 3e c9 4f 58 46 16 25 83 cf 0c 08 00 45 00|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|00 6c 1d 18 00 b9 78 11 20 7d 42 46 d6 a9 a7 72|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|00 6c 1d 18 00 b9 78 11 20 7d 42 46 d6 a9 a7 72|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|43 d1 c0 9d 12 cc 0a da ca b0 ae 0c 0a 46 e7 0c|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|43 d1 c0 9d 12 cc 0a da ca b0 ae 0c 0a 46 e7 0c|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|c9 26 6a 32 7f 67 72 55 25 a1 b4 cd 32 ee 6a 73|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|c9 26 6a 32 7f 67 72 55 25 a1 b4 cd 32 ee 6a 73|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|9f e3 4c 9e e4 9a 91 27 f8 ab f2 65 53 2d a6 31|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|9f e3 4c 9e e4 9a 91 27 f8 ab f2 65 53 2d a6 31|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|ee b9 66 e2 41 66 69 51 43 cc 68 d6 6c 04 9a 47|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|ee b9 66 e2 41 66 69 51 43 cc 68 d6 6c 04 9a 47|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|b5 a6 b8 ff 96 c9 f9 d4 06 06 16 1e 7d 74 46 b6|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|b5 a6 b8 ff 96 c9 f9 d4 06 06 16 1e 7d 74 46 b6|' -j DROP""",
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|f4 ab 42 f3 e2 c4 41 ae 40 57|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|f4 ab 42 f3 e2 c4 41 ae 40 57|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|43 d1 70 69 b0 8c 62 ff 1f c1 7b 67 c1 e2 b4 39|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|43 d1 70 69 b0 8c 62 ff 1f c1 7b 67 c1 e2 b4 39|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|4f 4a 85 8c 00 cf e5 f9 8d c9 4c 97 2d 11 b3 fe|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|4f 4a 85 8c 00 cf e5 f9 8d c9 4c 97 2d 11 b3 fe|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|99 fe 91 47 08 69 df 0a 33 a9 15 5e 51 97 2a dc|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|99 fe 91 47 08 69 df 0a 33 a9 15 5e 51 97 2a dc|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|1b 8b 96 9b c8 5b 52 33 11 62 d6 bd 2d 76 19 d1|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|1b 8b 96 9b c8 5b 52 33 11 62 d6 bd 2d 76 19 d1|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|d5 ef 93 86 40 a6 3d 75 26 f2 8f b5 c1 ac 80 de|' -j DROP """,
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|d5 ef 93 86 40 a6 3d 75 26 f2 8f b5 c1 ac 80 de|' -j DROP """,
        """iptables -I INPUT 1 -p udp --dport 1:65535 --match string --algo kmp --hex-string '|c6 2b 88 0a 70 48 a0 ce 74 5a|' -j DROP""",
        """iptables -I INPUT 1 -p udp --sport 1:65535 --match string --algo kmp --hex-string '|c6 2b 88 0a 70 48 a0 ce 74 5a|' -j DROP""",
        """iptables -A INPUT -p icmp --icmp-type=echo-reply -j ACCEPT""",
        """iptables -A INPUT -p icmp -j DROP""",
        ]
    print("Blocking Portscanning & ICMP through IP-Tables\nThis might take a while!")
    #run every command in z_list1:
    for item in z_list1:
        call(item, shell=True)
    print("[!] Done")