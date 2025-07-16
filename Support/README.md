## Hack The Box - Support (Retired) - Writeup

* Target IP Address: 10.10.11.174
* Operating System: Windows
  
# NMAP Scan
* Started off with a nmap scan.
* Command used: sudo nmap -sC -sV -vv -oA/support 10.10.11.174

 ![image](https://github.com/user-attachments/assets/e0242a40-4e22-4dfc-ac6b-c9e829f6f2be)

# Enumerating SMB
* I started off by enumerating SMB, since that was the only service listening.
* Command used: crackmapexec smb 10.10.11.174



 ![image](https://github.com/user-attachments/assets/de3e2da8-e565-4e36-b757-01bbafdb3f30)


* From the output, the name of the box is DC, and the domeain is support.htb
  
* Next, I am going to try and find file shares. Commaned Used: crackmapexec smb 10.10.11.174 --shares


  ![image](https://github.com/user-attachments/assets/09ea2ba8-5a19-4cd6-a40c-4baf6a09102d)

* I was not able to list file shares when using --shares. Going to try to use null authenticaiton.
* Command Used: crackmapexec smb 10.10.11.174 --shares -u '' -p ''


  ![image](https://github.com/user-attachments/assets/9df80fcb-2fba-4b34-bf4a-ad6eb4c47a6d)

* Still was not able to list file shares with null authentication. Going to try Anonymous authentication now.
* Command Used: crackmapexec smb 10.10.11.174 --shares -u 'NoUser' -p ''


  ![image](https://github.com/user-attachments/assets/3f599ae5-5a8f-4535-9ae8-86ef85610823)

* When putting 'NoUser' since I was trying anonymous authentication (the user does not actually exist, you could put anything) I got a list of file shares. Also, it listed the support-tools share. Which is a non standard share. It seems to be a custom SMB share for support staff. Currently with Read permissions.
* I am going to try to list the contents using smbclient.
* Command Used: smbclient -N //10.10.11.174/support-tools
* Was able to list the contents of the support-tools share.
  
  ![image](https://github.com/user-attachments/assets/1a392bb1-b523-47e1-9266-3386fa144280)

* I reconize what most of those applications are. Looks like there is 7zip, notepad ++, putty, systeminternals suite, and wireshark. The only one I do not reconize is UserInfo.exe.
* I am going to download UserInfo.exe to my machine using get. Command Used: get UserInfo.exe
* Contents of UserInfo:
  ![image](https://github.com/user-attachments/assets/d3594bbd-f650-4ab8-8c1c-2013ddd160d7)

* Looks like a bunch of .dll files, going to check to see if this a .NET application. NET applicaitons usually conatin configuration files. To check, command used: file UserInfo.exe



  ![image](https://github.com/user-attachments/assets/395a6878-1404-4865-8fd0-2b8a25225a96)

* This is a .NET Application. I have powershell and, dotnet framework installed on my machine. I can run this executable on my kali machine to see how it works without using a windows vm.
  ![image](https://github.com/user-attachments/assets/30d85b28-952b-4ba8-ac99-b6a0787ba793)

* Going to run the UserInfo.exe. Command used: ./UserInfo.exe -v find.
* ![image](https://github.com/user-attachments/assets/25da8ff8-deb0-4272-b134-ecbee3efbd45)
* Output is saying that -first or -last is required.
* I will trying using my ussername of my kali machine for the first name. Command Used: ./UserInfo.exe -v find -first charon
  ![image](https://github.com/user-attachments/assets/7bf583b3-0696-41a7-b591-83c6653c33fc)

* Going to open wireshark and run the command again. Since this program (UserInfo.exe) is a LDAP query I can use wireshark to see the exact packet contents from my machine to he LDAP server.I might be able to see a bind request.
* I opened wireshark and selected my tun0 interface because that is the network the machine is on. In the filter I entered LDAP to capture LDAP queries.
![image](https://github.com/user-attachments/assets/060d940a-0766-4edf-9a5b-14ca64eddf07)
I was able to capture a bind request. Right clicked on it and followed TCP stream and was able to see the username: ldap and the password for that user (ldap). The UserInfo.exe application was making a simple LDAP Bind over an unencrypted channel. Not using Kerberos. Also, the connection was made to TCP port 389 which is unencrypted.
![image](https://github.com/user-attachments/assets/9ee9aed3-a0f7-424e-b9ef-188e3dfcf7f1)

* Created a text document, copied and pasted the credentials.
## Using LDAP User to find new Shares
* Going to use crackmap using the ldap user and password
*   Results:
*   
  <img width="1218" height="239" alt="image" src="https://github.com/user-attachments/assets/76a3466f-ed63-4be5-9899-3b2828ec6573" />

* We can now have read permissions for NETLOGON and SYSVOL.
* I am going to use Bloodhound now.
* Command Used: python3 bloodhound.py -dns-tcp -ns 10.10.11.174 -d support.htb -u 'ldap' -p '<password>' -c all
* Results:
* <img width="1007" height="361" alt="image" src="https://github.com/user-attachments/assets/8b5d0718-2b98-4bb4-ad0a-36d621623f26" />
* The LDAP User is member of  Users@support.htb and Domain Users@support.htb
* <img width="1802" height="1183" alt="image" src="https://github.com/user-attachments/assets/352b9386-0dd8-4db6-bba0-212971aa370b" />
* Inbound Object Control
<img width="1720" height="451" alt="image" src="https://github.com/user-attachments/assets/a67bdd9a-f8d3-41f8-9b29-d8d57be8638c" />
* Did not find too much messing around in Bloodhound.

## Performing an LDAP search to identify plaintext passwords or sensitive data stored within the info attribute of Active Directory user objects.
* Going to use ldapsearch.
* Command used: ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w '<password>' -b 'dc=support,dc=htb' > ldap.out
* I used vim to open the ldap.out file to examine
* Found the user support and the password in the info file
* Results:
* <img width="716" height="420" alt="image" src="https://g`ithub.com/user-attachments/assets/a327167c-9ae2-4485-9539-b57a5680e791" />
* Going to use crackmap and the support user to get authentication.
* Command Used: crackmapexec smb 10.10.11.174 -u 'suport' -p '<password>'
* Results:
<img width="1216" height="86" alt="image" src="https://github.com/user-attachments/assets/1860bd5f-5368-4cb1-9ace-692ae99fc827" />
* I opened bloodhound up again and found the suppport user and marked it as owned.
* <img width="1795" height="775" alt="image" src="https://github.com/user-attachments/assets/e5209dc9-060f-4499-8b01-db6c5abb1d79" />
I changed my start path to  support@support.htb and changed the destination path to dc.support.htb.
<img width="1378" height="767" alt="image" src="https://github.com/user-attachments/assets/c77bd7be-abb9-4613-9c55-da63bf49cf2c" />

* Goind to examine the GenericAll Abuse.
* <img width="383" height="187" alt="image" src="https://github.com/user-attachments/assets/e0304af8-592c-4b64-8e9f-c502ce30a0cc" />
*Downloaded dependencies, powermad (https://github.com/Kevin-Robertson/Powermad)
* Made a directory called www and then copied powermad.ps1 to that directory.
* Next dependencie I downloaded what powersploit (https://github.com/PowerShellMafia/PowerSploit.git)
* I then copied powerview.ps1 from the Recon directory in PowerSploit to the www directory.
* Then I downloaded sharpcollection (https://github.com/Flangvik/SharpCollection).
* Then I copied Rubeus.exe from the sharpcollection/netframework_4.7_Any to the www directory.
* <img width="390" height="66" alt="image" src="https://github.com/user-attachments/assets/9de0cbcf-efd7-456d-b6da-a99ff14b268d" />
* Then I started up a http server
<img width="500" height="75" alt="image" src="https://github.com/user-attachments/assets/2ca1a516-9e4c-452e-81fa-2e20232dd03d" />
* started up evil-winrm using the support username and password.
* <img width="1049" height="228" alt="image" src="https://github.com/user-attachments/assets/094af755-c53e-49e0-b1fd-0f4562e5121b" />
* Changed to program data directory. Used the curl command to download rubeus on the machine.
* <img width="634" height="54" alt="image" src="https://github.com/user-attachments/assets/6d8cd209-92ef-4c46-9ae6-f7219241717f" />
* I downloaded Rubeus, PowerMad, and PowerView on the machine.
* <img width="944" height="95" alt="image" src="https://github.com/user-attachments/assets/9b5578de-596d-44c2-a9d1-9a3fb69c2b0a" />
## Beginning the Attack
* Before, I begin the attack I am going to make sure that I can create new machines.
* Command Used: Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota
* <img width="944" height="95" alt="image" src="https://github.com/user-attachments/assets/56f72761-cb5a-411c-905c-204ebe989a67" />
* Looks like 10 machines can be created.
* Going to follow the steps for the Generic All in BloodHound.
* First step.
* <img width="353" height="58" alt="image" src="https://github.com/user-attachments/assets/80f68be7-0c6b-4a30-8673-be61a7fc7442" />
Machine Account Added:
<img width="1075" height="61" alt="image" src="https://github.com/user-attachments/assets/8687ffa8-a384-4e88-8a8b-cc41feb9f013" />
* PowerView can be used to get the security identifier (SID) of the newly created computer account.
* <img width="358" height="65" alt="image" src="https://github.com/user-attachments/assets/6af26f6f-c467-4edc-a08b-58ffb0025de6" />
* Got the SID of the computer account.
* <img width="934" height="78" alt="image" src="https://github.com/user-attachments/assets/bf98c065-8764-443b-8ded-e37144557da0" />
* Now we need to build the ACE with the computer SID as the principal and get the binary bytes.
* <img width="352" height="89" alt="image" src="https://github.com/user-attachments/assets/4deca256-027c-441c-840f-9ea6b7431a07" />
* <img width="1331" height="73" alt="image" src="https://github.com/user-attachments/assets/3a502ae7-415e-4206-a6a1-b5de49c385cf" />
* Next Step.
* <img width="357" height="139" alt="image" src="https://github.com/user-attachments/assets/523a8914-d1d3-4dce-8afe-49613f0b7253" />
* Now I can use Rubeus to hash the plaintext password into its RC4_HMAC form.
* <img width="667" height="363" alt="image" src="https://github.com/user-attachments/assets/460a9f87-0b85-4c84-a54a-69acfe3e4b9a" />
* Next,
* <img width="356" height="84" alt="image" src="https://github.com/user-attachments/assets/825d203c-a53c-42f0-ae46-54b2091e08e2" />
<img width="355" height="83" alt="image" src="https://github.com/user-attachments/assets/0ae5f5fa-93cc-48fd-a914-13f8e9cf6fa3" />







































