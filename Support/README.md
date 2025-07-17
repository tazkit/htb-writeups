## Hack The Box - Support (Retired) - Writeup

* Target IP Address: 10.10.11.174
* Operating System: Windows
  
# Initial Reconnaissance 
* Started off with a nmap scan.
* Command used: sudo nmap -sC -sV -vv -oA/support 10.10.11.174

* This revealed that the machine was running a number of Windows services, including:
    - 88/tcp - Kerberos
    - 389/tcp - LDAP
    - 445/tcp - SMB
    - 5985/tcp - WinRM
* From the banner information, I identified the host as a Domain Controller (DC) in the domain support.htb.

 ![image](https://github.com/user-attachments/assets/e0242a40-4e22-4dfc-ac6b-c9e829f6f2be)

# Enumerating SMB
* I decided to begin enumeration with SMB, given that it was exposed on port 445.
* USing crackmapexec, I attpempted to list available shares:
* Command used: crackmapexec smb 10.10.11.174


 ![image](https://github.com/user-attachments/assets/de3e2da8-e565-4e36-b757-01bbafdb3f30)



  ![image](https://github.com/user-attachments/assets/09ea2ba8-5a19-4cd6-a40c-4baf6a09102d)

* I was not able to list file shares when using --shares. Going to try to use null authenticaiton.
* Command Used: crackmapexec smb 10.10.11.174 --shares -u '' -p ''


 ![image](https://github.com/user-attachments/assets/9df80fcb-2fba-4b34-bf4a-ad6eb4c47a6d)

* Still was not able to list file shares with null authentication. Going to try Anonymous authentication now.
* Command Used: crackmapexec smb 10.10.11.174 --shares -u 'NoUser' -p ''


  ![image](https://github.com/user-attachments/assets/3f599ae5-5a8f-4535-9ae8-86ef85610823)

* When putting 'NoUser' since I was trying anonymous authentication (the user does not actually exist, you could put anything) I got a list of file shares. Also, it listed the support-tools share. Which is a non standard share. It seems to be a custom SMB share for support staff. Currently with Read permissions.

## Accesing support-tools

* Using smbclient, I connected to the share.
* Command Used: smbclient -N //10.10.11.174/support-tools
* Was able to list the contents of the support-tools share.
  
  ![image](https://github.com/user-attachments/assets/1a392bb1-b523-47e1-9266-3386fa144280)

* This share contained a number of useful executables like 7-Zip, Notepad++, and SysInternals, but one file stood out — UserInfo.exe. I downloaded it for further inspection.
* Command Used: get UserInfo.exe
* Contents of UserInfo:
  ![image](https://github.com/user-attachments/assets/d3594bbd-f650-4ab8-8c1c-2013ddd160d7)

## Reverse Engineering UserInfo.exe
* First, I ran file to check the binary format:
  
 ![image](https://github.com/user-attachments/assets/395a6878-1404-4865-8fd0-2b8a25225a96)

* This confirmed it was a .NET application. I inspected the extracted contents, and among the .dll files was something interesting: user_ldap_creds.txt.

   ![image](https://github.com/user-attachments/assets/d3594bbd-f650-4ab8-8c1c-2013ddd160d7)

## Capturing Credentials with Wireshark

* I suspected this tool performed LDAP queries, so I executed UserInfo.exe.
* Command used: ./UserInfo.exe -v find.
* ![image](https://github.com/user-attachments/assets/25da8ff8-deb0-4272-b134-ecbee3efbd45)

* Output is saying that -first or -last is required.
* I will trying using my ussername of my kali machine for the first name. Command Used: ./UserInfo.exe -v find -first charon
  ![image](https://github.com/user-attachments/assets/7bf583b3-0696-41a7-b591-83c6653c33fc)

* Going to open wireshark and run the command again. Since this program (UserInfo.exe) is a LDAP query I can use wireshark to see the exact packet contents from my machine to the LDAP server. I might be able to see a bind request.
* I opened wireshark and selected my tun0 interface because that is the network the machine is on. In the filter I entered LDAP to capture LDAP queries.
![image](https://github.com/user-attachments/assets/060d940a-0766-4edf-9a5b-14ca64eddf07)
I was able to capture a bind request. Right clicked on it and followed TCP stream and was able to see the username: ldap and the password for that user (ldap). The UserInfo.exe application was making a simple LDAP Bind over an unencrypted channel. Not using Kerberos. Also, the connection was made to TCP port 389 which is unencrypted.
![image](https://github.com/user-attachments/assets/9ee9aed3-a0f7-424e-b9ef-188e3dfcf7f1)

* Created a text document, copied and pasted the credentials.
  
## Using LDAP User to find new Shares
* Using crackmapexec and the discovered creds, I am going to try and find new SMB shares.
*   Results:   
  <img width="1218" height="239" alt="image" src="https://github.com/user-attachments/assets/76a3466f-ed63-4be5-9899-3b2828ec6573" />

* I now have read permissions for NETLOGON and SYSVOL. These typically contain GPOs, scripts, or other sensitive domain config data.

##  BloodHound Analysis

* To map potential privilege escalation paths, I used BloodHound.
* Command Used: python3 bloodhound.py -dns-tcp -ns 10.10.11.174 -d support.htb -u 'ldap' -p '<password>' -c all
* Results:
 <img width="1007" height="361" alt="image" src="https://github.com/user-attachments/assets/8b5d0718-2b98-4bb4-ad0a-36d621623f26" />
* The LDAP User is member of  Users@support.htb and Domain Users@support.htb
 <img width="1802" height="1183" alt="image" src="https://github.com/user-attachments/assets/352b9386-0dd8-4db6-bba0-212971aa370b" />
<img width="1720" height="451" alt="image" src="https://github.com/user-attachments/assets/a67bdd9a-f8d3-41f8-9b29-d8d57be8638c" />
* After uploading the data to the BloodHound GUI, I discovered that while the LDAP user didn’t have admin privileges, it had inbound object control via a group with GenericAll permissions on a domain object — specifically the msDS-KeyCredentialLink attribute of the DC.
<img width="1378" height="767" alt="image" src="https://github.com/user-attachments/assets/c77bd7be-abb9-4613-9c55-da63bf49cf2c" />
* This meant I could abuse Shadow Credentials to impersonate a high-privileged user.

## Performing an LDAP search to identify plaintext passwords or sensitive data stored within the info attribute of Active Directory user objects.
* Going to use ldapsearch.
* Command used: ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w '<password>' -b 'dc=support,dc=htb' > ldap.out
* I used vim to open the ldap.out file to examine
* Found the user support and the password in the info file
  <img width="709" height="417" alt="image" src="https://github.com/user-attachments/assets/02e3f33b-8904-455e-a1a8-a8a6d6f74bb5" />

* Going to use crackmap and the support user to get authentication.
* Command Used: crackmapexec smb 10.10.11.174 -u 'suport' -p '<password>'

<img width="1216" height="86" alt="image" src="https://github.com/user-attachments/assets/1860bd5f-5368-4cb1-9ace-692ae99fc827" />

## Shadow Credentials Exploitation

* Goind to examine the GenericAll Abuse.
 <img width="383" height="187" alt="image" src="https://github.com/user-attachments/assets/e0304af8-592c-4b64-8e9f-c502ce30a0cc" />


* Dependencies Used:
  - Powerdmad (https://github.com/Kevin-Robertson/Powermad)
  - PowerSploit (https://github.com/PowerShellMafia/PowerSploit.git)
  - Rubeus (from the sharpcollection/netframework_4.7_Any)

 <img width="390" height="66" alt="image" src="https://github.com/user-attachments/assets/9de0cbcf-efd7-456d-b6da-a99ff14b268d" />




* I started up a http server to donwload dependencies on the target machine.
<img width="500" height="75" alt="image" src="https://github.com/user-attachments/assets/2ca1a516-9e4c-452e-81fa-2e20232dd03d" />


* To get remote access I used evil-wrinrm
* <img width="1049" height="228" alt="image" src="https://github.com/user-attachments/assets/094af755-c53e-49e0-b1fd-0f4562e5121b" />
* Changed to program data directory. Used the curl command to download rubeus on the machine.
* <img width="634" height="54" alt="image" src="https://github.com/user-attachments/assets/6d8cd209-92ef-4c46-9ae6-f7219241717f" />
* I downloaded Rubeus, PowerMad, and PowerView on the machine.
* <img width="944" height="95" alt="image" src="https://github.com/user-attachments/assets/9b5578de-596d-44c2-a9d1-9a3fb69c2b0a" />
* Before, I begin the attack I am going to make sure that I can create new machines.
* Command Used: Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota
 <img width="944" height="95" alt="image" src="https://github.com/user-attachments/assets/56f72761-cb5a-411c-905c-204ebe989a67" />

* Looks like 10 machines can be created.
* Going to follow the steps for the Generic All in BloodHound.
* First step, add a machine account: New-MachineAccount -MachineAccount attackersyst -Password 'Summer2021!' -AsPlainText -Force

  <img width="353" height="58" alt="image" src="https://github.com/user-attachments/assets/80f68be7-0c6b-4a30-8673-be61a7fc7442" />

Machine Account Added:
<img width="1075" height="61" alt="image" src="https://github.com/user-attachments/assets/8687ffa8-a384-4e88-8a8b-cc41feb9f013" />

* Next, is to get the machine SID. PowerView can be used to get the security identifier (SID) of the newly created computer account
  <img width="358" height="65" alt="image" src="https://github.com/user-attachments/assets/6af26f6f-c467-4edc-a08b-58ffb0025de6" />

* Got the SID of the computer account.
  <img width="934" height="78" alt="image" src="https://github.com/user-attachments/assets/bf98c065-8764-443b-8ded-e37144557da0" />

* Now we need to build the ACE with the computer SID as the principal and get the binary bytes.
 <img width="352" height="89" alt="image" src="https://github.com/user-attachments/assets/4deca256-027c-441c-840f-9ea6b7431a07" />
 <img width="1331" height="73" alt="image" src="https://github.com/user-attachments/assets/3a502ae7-415e-4206-a6a1-b5de49c385cf" />

* Generating a TGT with Rubeus
<img width="667" height="363" alt="image" src="https://github.com/user-attachments/assets/460a9f87-0b85-4c84-a54a-69acfe3e4b9a" />



TGT Ticket Generated with Rubeus:

<img width="698" height="595" alt="image" src="https://github.com/user-attachments/assets/b40ddd42-f090-494c-a713-b12f2c510574" />

* I used ticketconverter.py from Impacket to convert the ticket to a .ccahce file.

## Remote Execution with PSExec
*  I used psexec.py from Impacket with Kerberos auth:

<img width="1129" height="344" alt="image" src="https://github.com/user-attachments/assets/0230a112-6252-4ff3-8ccf-23837c71511b" />


* I changed the directory to \user\administrator\desktop and found root.txt file.

<img width="417" height="239" alt="image" src="https://github.com/user-attachments/assets/52c6c52d-1b16-4d4c-8b5f-354ba719bcf1" />












































