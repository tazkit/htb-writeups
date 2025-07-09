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

  











