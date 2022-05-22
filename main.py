#import all the Commands from the Brain(Flaway.py) 
# im using Static Linking to Save File space.
from flaway import (secure__Ports__, 
                    block__port__scanner__,
                    firewall__setup__, 
                    reconfigure_secure_shell__,
                    check_for_update__, 
                    antivirus_software__,
                    startup_service__,)
#make a copy in memory of the settings File
with open('settings') as file_pointer1:
    content1 = file_pointer1.readlines()

installation = False
for settings in content1:
    arch1 = settings.split(':')
    arch1 = arch1[1]
    if content1.index(settings) == 0:
        if "TRUE" in arch1.upper():
            #Installing AntiVirus Software
            print("\t[ INSTALL ANTI VIRUS SOFTWARE ]")
            name = input("FILE NAME : ")
            try:
                antivirus_software__(name)
            except:
                print("[!] Something went wrong installing anti virus software")
            else:
                installation = True
    if content1.index(settings) == 1:
        if "TRUE" in arch1.upper():
            if installation:
                #Making The Antivirus Software a Startup Service 
                description   = input("App Desription   : ")
                filelocations = input("APP DIR LOCATION : ")
                filename      = input("File Name        :")
                try:
                    startup_service__(description, filelocations, filename)
                except:
                    print("[!] Something went wrong creating a startup process")
    if content1.index(settings) == 2:
        if "TRUE" in arch1.upper():
            #configuring fish this might take a while
            from subprocess import check_output
            #make Fish your default kernel
            print("[!] Installing Fish as a Default Kernel(This will take a while)")
            try:
                check_output('sudo apt-get install fish -y', shell=True)
                check_output("echo /bin/fish >> /$USER/.bashrc", shell=True)
            except:
                print("Add FIsh as a REPO (sudo apt-add-repository ppa:fish-shell/release-3)")
            print("Fish is now your default console")

    if content1.index(settings) == 3:
        if "TRUE" in arch1.upper():
            #block ICMP & stealthy port scanning
            try:
                block__port__scanner__()
            except:
                print("[!] Something went wrong")
    if content1.index(settings) == 4:
        if "TRUE" in arch1.upper():
            #Securing Your Machines Ports from simple DOS attacks
            try:
                secure__Ports__()
            except:
                print("[!] Something Went Wrong")
    if content1.index(settings) == 5:
        if "TRUE" in arch1.upper():
            #installing Netfilter Persistant
            try:
                firewall__setup__()
            except:
                print("[!] Something Went Wrong")
    if content1.index(settings) == 6:
        if "TRUE" in arch1.upper():
            #Updating & Upgrading Kernel
            try:
                check_for_update__()
            except:
                print("[!] Something went wrong")
    #change your Secure Shell port (This will change any configurations you already have set)
    if content1.index(settings) == 7:
        if "TRUE" in arch1.upper():
            print(" What Port would you like to use ? ")
            while True:
                try:
                    PORT = input(" $ PORT :")
                except ValueError:
                    continue
            try:
                reconfigure_secure_shell__()
            except:
                print("[!] Something went wrong")