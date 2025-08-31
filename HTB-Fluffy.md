# HTB - Fluffy

Fluffy

HackTheBox - Fluffy

Target IP Address: 10.10.11.69

Operating System: Windows

# *Reconnaissance*

Nmap Scan

Command Used: ***sudo nmap -sC -sV -A -p- 10.10.11.69 -oN fluffy_nmap.txt***

| **Port** | **State** | **Service** | **Version** |
| --- | --- | --- | --- |
| 53/tcp | open | domain | Simple DNS Plus |
| 88/tcp | open | kerberos-sec | Microsoft Windows Kerberos |
| 135/tcp | open | msrpc | Microsoft Windows RPC |
| 139/tcp | open | netbios-ssn | Microsoft Windows netbios-ssn |
| 389/tcp | open | ldap | Microsoft Windows Active Directory LDAP (Domain: fluffy.htb) |
| 445/tcp | open | microsoft-ds | Windows SMB |
| 464/tcp | open | kpasswd5 | Kerberos kpasswd |
| 593/tcp | open | ncacn_http | Microsoft Windows RPC over HTTP |
| 636/tcp | open | ldapssl | Microsoft Windows Active Directory LDAP over SSL |
| 3269/tcp | open | ldapssl | Microsoft Windows Active Directory LDAP over SSL |
| 5985/tcp | open | http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |

**Key Observations:**

- Multiple LDAP and Kerberos-related ports suggest this is an Active Directory (AD) environment.
- Port 5985 (WinRM) is open, which could be useful for remote command execution.
- Domain name identified: `fluffy.htb`

## **Initial Access – Provided Credentials**

This box provides you with a low lever user credentials to simulate what a low-privileged insider or compromised workstation account could access. This simulates a **post-phishing or credential-leak scenario**, where attackers already have a foothold but want to escalate privileges.

Domain user account:

Username: j.fleischman
Password: J0elTHEM4n1990!

# Enumeration

After obtaining initial access using the provided credentials, I began by verifying SMB access with `crackmapexec`. My goal here was to confirm the credentials were valid.

<img width="3488" height="204" alt="image" src="https://github.com/user-attachments/assets/d4827c6b-70be-4760-a90d-f15a8ad97dea" />


Next, I enumerated the available SMB shares to identify potential avenues for further exploration:

<img width="3490" height="602" alt="image" src="https://github.com/user-attachments/assets/fa35ce0c-6923-44eb-a472-01392c412ebb" />


What stood out here was the `IT` share — I had both read and write access to it. This could be an opportunity to upload a payload or manipulate existing files if I find something being executed by a higher-privileged user.

# Accessing the IT share

Using smbclient to access the IT share:

<img width="2490" height="904" alt="image" src="https://github.com/user-attachments/assets/2fba3bf3-ccf9-4bdf-b7c6-7b9aa26f579f" />


Once authenticated, I ran `dir` to list the contents of the share. The directory contained several files and folders that immediately stood out:

- `KeePass-2.58.zip` (3.2 MB)
- `payload.library-ms` (365 bytes)
- `Everything-1.4.1.1026.x64.zip` (1.8 MB)
- `Upgrade_Notice.pdf`

Using the get command to download files to machine:

<img width="3498" height="206" alt="image" src="https://github.com/user-attachments/assets/5916f420-5cf7-460d-bc67-86a3e66c7031" />


First I wanted to inspect the Upgrade_Notice.pdf:

<img width="1268" height="1684" alt="image" src="https://github.com/user-attachments/assets/75ab56eb-3a51-4859-9aed-a2a7ab3c86ed" />


| CVE ID | Severity | Notes |
| --- | --- | --- |
| **CVE-2025-24996** | Critical | Likely remote code execution or privilege escalation vulnerability |
| **CVE-2025-24071** | Critical | Possibly related to SMB, RPC, or AD misconfigurations |
| **CVE-2025-46785** | High | Could involve application-level privilege escalation |
| **CVE-2025-29968** | High | Possibly a local privilege escalation |
| **CVE-2025-21193** | Medium | May relate to Windows feature bypass |
| **CVE-2025-3445** | Low | Most likely informational or minor misconfig |

I started by looking up each CVE and noticed something interesting with CVE-2025-24071:

<img width="1280" height="1512" alt="image" src="https://github.com/user-attachments/assets/ebdec897-f177-4ba2-a459-07c21e09cdca" />


- This vulnerability resides in how Windows Explorer handles ‘.library-ms’ files.
- From earlier, I notice a file in the SMB share ‘IT’ called `payload.library-ms`.

# Exploitation of CVE-2025-24071

During enumeration, I discovered that the target was vulnerable to **CVE-2025-24071**, a recently disclosed flaw affecting Microsoft Windows library handling. The vulnerability allows for the disclosure of **NTLMv2 hashes** when a specially crafted `.library-ms` file is opened from a remote share.

To exploit this, I located a **public Proof-of-Concept (PoC)** script on GitHub that automates the creation of the malicious payload. Using the script, I generated a payload file (`payload.library-ms`) which, once opened on the target, forces the system to authenticate to my attacking machine and leak NTLMv2 credentials. : https://github.com/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-/blob/main/POC/CVE-2025-24071.py

The command I executed was:

python3 <pocscript> payload 10.10.14.41

This created the malicious payload successfully, as shown in the screenshot. The payload was then prepared for delivery to the target.

<img width="3472" height="630" alt="image" src="https://github.com/user-attachments/assets/c9bb26f4-7f42-478d-a4f1-e21eede4f799" />


**Delivering the Malicious Payload via SMB**

After creating the malicious `.library-ms` payload using the CVE-2025-24071 PoC, the next step was to deliver it to the target system. During enumeration, I had discovered valid SMB credentials (`j.fleischman`) that allowed me to access the `IT` share on the target.

<img width="3002" height="1290" alt="image" src="https://github.com/user-attachments/assets/822493a5-d3e5-49f3-b21f-48c4e132313f" />


After placing the malicious `.library-ms` payload onto the SMB share, I set up **Responder** on my attacking machine to capture any outbound NTLM authentication attempts that would occur when a user interacted with the payload.

<img width="3484" height="210" alt="image" src="https://github.com/user-attachments/assets/0a90d428-5ab6-45fd-86d8-89c04d237d6f" />


At this point, I had a valid NTLMv2 hash for `p.agila`, which could be cracked to recover the user’s plaintext password. This step was critical because it allowed me to escalate from just uploading a payload to having valid domain credentials.

Using the NTLMv2 hash I had captured earlier, I ran **John the Ripper** with the `netntlmv2` format and the `rockyou.txt` wordlist to get the password.

<img width="3476" height="818" alt="image" src="https://github.com/user-attachments/assets/720a87f6-43aa-425c-baad-63a63519cdbf" />


# BloodHound Analysis

After successfully capturing and cracking an NTLMv2 hash, I obtained valid credentials for the domain user `p.agila@fluffy.htb`. To assess this user's privileges within the domain and identify potential escalation paths, I used the Python-based BloodHound collector, `bloodhound.py`, which allows for LDAP and Kerberos-based enumeration directly from my Kali machine without needing to execute code on the target.

The graph revealed the following:

- The account `p.agila@FLUFFY.HTB` is a member of **Domain Users**.
- More importantly, it is also a member of the **Service Account Managers** group.
- This group membership indicated potential elevated rights, such as managing or modifying service accounts.

This discovery was a key finding, as service account management rights often enable **persistence or privilege escalation** paths within Active Directory.

<img width="1724" height="796" alt="image" src="https://github.com/user-attachments/assets/73088592-313d-451d-8f7c-7617845332e3" />


### BloodHound Pathfinding – Escalation to `WINRM_SVC`

Using BloodHound’s **pathfinding** feature, I mapped out how my compromised user `p.agila@fluffy.htb` could escalate privileges further.

The path revealed:

1. **`p.agila` is a member of the Service Account Managers group.**
    - This group has **GenericAll** rights over the **Service Accounts group**.
2. **Service Accounts group** has **GenericWrite** rights over the account `WINRM_SVC@fluffy.htb`.
    - This means members of the group can modify attributes of the `WINRM_SVC` account, including adding authentication material such as Shadow Credentials.
3. By leveraging this chain of rights (GenericAll → GenericWrite), I was able to **take over the `WINRM_SVC` account**.
    - This provided a pivot into a more privileged context within the domain.

<img width="2164" height="810" alt="image" src="https://github.com/user-attachments/assets/c3a20924-820d-4217-878a-57354409d4e8" />


### Exploiting Group Membership with BloodyAD

From the BloodHound analysis, I knew that my user `p.agila` (with the password `prometheusx-303`) had sufficient rights to manage **Service Account groups**. To weaponize this, I used **BloodyAD**, a tool designed for Active Directory object manipulation.

<img width="2152" height="116" alt="image" src="https://github.com/user-attachments/assets/0bd713aa-7fce-4813-8040-d15645b1d60b" />


### Kerberoasting with TargetedKerberoast

With `p.agila`’s credentials (`prometheusx-303`), I attempted a **Kerberoast attack** to see if any service accounts had weakly protected Kerberos service tickets. To do this, I ran the tool **targetedKerberoast.py** against the domain:

<img width="3480" height="1256" alt="image" src="https://github.com/user-attachments/assets/4bc3179c-90e9-4015-9181-bae50216ede3" />


- The tool queried Active Directory via LDAP for accounts with **Service Principal Names (SPNs)**.
- It then requested **TGS tickets** for those accounts, which were returned in a format suitable for offline password recovery.

As shown in the output, the tool successfully dumped **Kerberos hashes** for multiple service accounts, including:

- `ca_svc`
- `ldap_svc`
- `winrm_svc`

These hashes are not immediately usable credentials. Instead, they represent an opportunity to attempt password recovery using wordlists. Even if they are not cracked, simply obtaining them confirms that the accounts are vulnerable to Kerberoasting and could potentially be abused if weak passwords are in use.

This step provided me with additional targets (`ca_svc` and `winrm_svc`) that became critical in the escalation path.

I used **Certipy’s Shadow Credentials attack** against the `WINRM_SVC` account. Since I already had valid credentials for the user `p.agila`, I authenticated with those and specified `WINRM_SVC` as the target. Certipy automatically generated a malicious certificate and key credential, then added it to the `WINRM_SVC` account. This allowed me to impersonate `WINRM_SVC` and request a Ticket Granting Ticket (TGT). Certipy then restored the account’s original key credentials so everything appeared normal, but at this point I had successfully obtained valid credentials for `WINRM_SVC`. This gave me a stronger foothold in the environment and positioned me for further privilege escalation.

<img width="2156" height="906" alt="image" src="https://github.com/user-attachments/assets/59904ee6-f1cd-4c13-bced-b499dee9f7b2" />


After obtaining the NTLM hash for the `WINRM_SVC` account, I used **Evil-WinRM** to establish a remote session on the target machine. Evil-WinRM is a common post-exploitation tool that allows authenticated access to a Windows system over WinRM.

I supplied the machine’s IP address (`10.10.11.69`), the username (`winrm_svc`), and the NTLM hash I had previously extracted. The authentication was successful, and I gained an interactive PowerShell session as the `WINRM_SVC` account.

Once inside, I navigated to the user’s desktop directory and confirmed the presence of the `user.txt` file, which validated that I had successfully compromised this account and obtained user-level access to the system.

<img width="2152" height="876" alt="image" src="https://github.com/user-attachments/assets/256fb80b-cff3-4681-b763-7b1d0ad0825b" />


To further enumerate Active Directory Certificate Services (ADCS), I used **Certipy** to query the attributes of the `ca_svc` account. I authenticated with the `p.agila@fluffy.htb` user and the password I had previously obtained (`prometheusx-303`).

By running the `certipy account` command against the domain controller at `10.10.11.69`, I was able to retrieve detailed information about the `ca_svc` service account. The output confirmed key attributes such as:

- **Distinguished Name:** CN=certificate authority service, CN=Users, DC=fluffy, DC=htb
- **Service Principal Name (SPN):** `ADCS/ca.fluffy.htb`
- **User Principal Name:** `ca_svc@fluffy.htb`
- **Object SID** and **account creation/change timestamps**

This confirmed that `ca_svc` was a Certificate Authority service account tied to ADCS, making it a potential target for certificate-based abuse techniques in order to escalate privileges.

<img width="2158" height="754" alt="image" src="https://github.com/user-attachments/assets/96b72e14-c01f-4b7e-9849-0ab45e845444" />


After confirming information about the `ca_svc` account, I moved forward by abusing Active Directory Certificate Services (ADCS) with **PyWhisker**. I ran the tool while authenticated as the `WINRM_SVC` account using its NTLM hash.

My goal was to add a malicious KeyCredential to the `ca_svc` account. PyWhisker generated a new certificate and corresponding KeyCredential, then updated the `msDS-KeyCredentialLink` attribute of the `ca_svc` object. This effectively linked my certificate to the service account, giving me the ability to authenticate as `ca_svc` through certificate-based authentication.

The tool also saved the generated certificate and private key as a PFX file (`i1EqdNk4.pfx`) protected with a password, which I could later use with PKINIT tools to obtain a Ticket-Granting Ticket (TGT).

This step was important because it allowed me to escalate access by leveraging the `ca_svc` account, which has higher privileges in the domain.

<img width="1994" height="518" alt="image" src="https://github.com/user-attachments/assets/ec4dc0f0-5aa4-413a-8742-37b5b1d631df" />


After generating a certificate and private key for the `ca_svc` account with PyWhisker, I used **PKINITtools** to request a Kerberos Ticket-Granting Ticket (TGT) for that account.

I ran the `gettgtpkinit.py` script and provided:

- The PFX certificate file (`i1EqdNk4.pfx`) created earlier.
- The password (`nUTNZhWbyt0Araf4pE6L`) used to protect the PFX.
- The domain controller’s IP (`10.10.11.69`).
- The domain and username (`fluffy.htb/ca_svc`).

The tool successfully loaded the certificate and authenticated as `ca_svc` using PKINIT (Public Key Cryptography for Initial Authentication in Kerberos). It then requested and received a valid TGT for `ca_svc`.

The output shows:

- An **AS-REP encryption key** (useful if needed later).
- Confirmation that the **TGT was issued and saved** into a credential cache file (`ca_svc.ccache`).

This step was crucial because now I had a valid Kerberos TGT for `ca_svc`, meaning I could impersonate that account and use its privileges for further actions in the domain.

<img width="2244" height="394" alt="image" src="https://github.com/user-attachments/assets/d9d5eb27-faf0-478a-bbfa-6954f6aade3e" />


After obtaining a valid Kerberos TGT for the `ca_svc` account, I exported it into my environment by setting the `KRB5CCNAME` variable. This allowed me to use the ticket for authentication without needing the account’s password.

Next, I used **Certipy** to request a new certificate for `ca_svc`. I specified:

- The account (`ca_svc@fluffy.htb`).
- The domain controller’s IP (`10.10.11.69`) and hostname (`DC01.fluffy.htb`).
- The target CA (`fluffy-DC01-CA`).
- The certificate template (`User`).

Since I was already authenticated through the Kerberos ticket, Certipy submitted the request and the CA issued a valid certificate for `ca_svc`.

The tool confirmed that the certificate was successfully generated and saved to a `.pfx` file (`ca_svc.pfx`) along with the private key.

This was an important step because I now had a reusable certificate that could authenticate me as `ca_svc` whenever I needed, effectively giving me persistent and passwordless access to that account.

<img width="1560" height="900" alt="image" src="https://github.com/user-attachments/assets/0972c546-703d-4a64-bf98-5cc1c2224f6c" />


At this stage, I used the certificate I had previously generated for the `ca_svc` account to authenticate directly against the domain controller. I did this with the `certipy-ad auth` command, pointing it to the `.pfx` file and specifying the domain controller’s IP (`10.10.11.69`).

The tool read the certificate and confirmed my identity as `ca_svc@fluffy.htb`. With this, I was able to successfully request and receive a **Kerberos Ticket Granting Ticket (TGT)** for the `ca_svc` account. Certipy then stored this ticket in a credential cache file (`ca_svc.ccache`).

Afterward, Certipy automatically attempted to extract the **NTLM hash** for the `ca_svc` account. The process succeeded, and I obtained the NT hash associated with `ca_svc@fluffy.htb`.

From my perspective, this was a critical point because I now had both:

- A valid Kerberos ticket for authentication.
- The NTLM hash for `ca_svc`, which could be reused in other attacks or authentication scenarios.

This solidified my access to the `ca_svc` account and gave me multiple ways to continue escalating my privileges in the domain.

<img width="1822" height="566" alt="image" src="https://github.com/user-attachments/assets/6ce31fe0-78bb-4c1d-aa4a-7735b779b31c" />


At this stage, I used **Certipy** to enumerate vulnerable certificate templates within the target’s Active Directory Certificate Services (AD CS) environment. Since I had already compromised the `ca_svc` account and obtained its NTLM hash, I authenticated as `ca_svc@fluffy.htb` with the `--hashes` option.

The command (`certipy-ad find --vulnerable`) queried the domain controller (`10.10.11.69`) and the certificate authority (`fluffy-DC01-CA`) to gather details about:

- Available **certificate templates** (33 were found).
- The configured **certificate authorities** (1 was found).
- Enabled **certificate templates** (11 were enabled).
- Issuance policies and OIDs linked to templates.

Although there were some warnings (like failing to connect to the remote registry and timeouts while checking web enrollment), Certipy still successfully retrieved the configuration of the certificate authority.

The results were saved into both a text file and a JSON file for later analysis (`20250810065752_Certipy.txt` and `20250810065752_Certipy.json`).

 This step was about **enumerating AD CS misconfigurations**. I was looking for vulnerable certificate templates that could be abused (e.g., ESC1, ESC2, ESC8 attacks) to escalate privileges further, possibly all the way to **Domain Admin**.

<img width="1384" height="918" alt="image" src="https://github.com/user-attachments/assets/c945a722-0388-4d5f-8c03-9d68cde36335" />



The output shows the results of enumerating the Certificate Authority (**fluffy-DC01-CA**) using Certipy.

Key details from the enumeration:

- **CA Information**:
    - CA Name: `fluffy-DC01-CA`
    - Host: `DC01.fluffy.htb`
    - Certificate subject and validity details were successfully retrieved.
    - Requests must be encrypted, and the CA issues certificates under the Microsoft default policy.
- **Web Enrollment**:
    - Both HTTP and HTTPS enrollment are disabled, so web-based certificate requests are not possible.
- **Permissions**:
    - Only privileged groups such as `Domain Admins`, `Enterprise Admins`, `Administrators`, and `Cert Publishers` have rights to manage the CA or issue certificates.
- **Vulnerability**:
    - Certipy flagged **ESC16** (Security Extension Disabled). This means the CA is missing protections that normally enforce certificate security.

<img width="1640" height="954" alt="image" src="https://github.com/user-attachments/assets/09622cfa-d0f4-4bc9-aa29-744665ba1ec5" />


At this stage, I used **Certipy** to request a certificate as the **Administrator** account. I authenticated with the `ca_svc@fluffy.htb` account against the Certificate Authority (`fluffy-DC01-CA`) and specified the **User** template. Instead of generating the certificate for myself, I set the UPN to `administrator@fluffy.htb`.

The request was successful, and the CA issued me a valid certificate for the Administrator account. Certipy saved the certificate and private key into a `.pfx` file, which means I now hold credentials that can be used to authenticate as the domain Administrator.

This step gave me the ability to impersonate the highest-privileged user in the domain and effectively escalate to full domain admin access.

<img width="2428" height="354" alt="image" src="https://github.com/user-attachments/assets/c5e05f90-ca6e-4a0b-94a9-77f619273749" />


At this point, I used **Certipy** again, but this time to update the attributes of the `ca_svc` account. Specifically, I changed its **UserPrincipalName (UPN)** to impersonate the domain Administrator by setting it to `administrator@fluffy.htb`.

By doing this, I effectively made the `ca_svc` account act as if it were the Administrator account in Kerberos authentication contexts. Certipy confirmed the update, showing that the UPN for `ca_svc` was successfully modified.

This meant that when I later requested Kerberos tickets using the `ca_svc` account, they would actually be issued for the Administrator identity. In practice, this allowed me to escalate my access and take over the domain Administrator role.

<img width="1640" height="722" alt="image" src="https://github.com/user-attachments/assets/38704c15-2185-43a6-8673-2aadeecbaefc" />


I used **PKINITtools** to authenticate as the domain administrator with the forged certificate I created earlier. The command I ran specified the Administrator’s PFX certificate (`administrator_sid.pfx`), which had no password, and requested a Kerberos Ticket Granting Ticket (TGT) for the account `FLUFFY.HTB/Administrator`. I chose to save the ticket into a file called `administrator.ccache`.

The tool loaded the certificate and private key, then performed PKINIT against the domain controller. The DC accepted the certificate as valid proof of identity for the Administrator account and returned an AS-REP response. This confirmed that I had successfully authenticated.

Finally, the TGT was saved to `administrator.ccache`. With this file, I can now load it into my environment and use Kerberos authentication as the domain administrator, effectively giving me full domain admin access without needing the actual password.

<img width="1986" height="578" alt="image" src="https://github.com/user-attachments/assets/5f2d2064-6f6a-4b33-b45a-a642cfdaf312" />


After manipulating the `ca_svc` account and leveraging certificate services, I was able to request a certificate for the domain administrator account. With that certificate in hand, I used **Certipy** to authenticate as `administrator@fluffy.htb`.

I pointed Certipy to the domain controller (`10.10.11.69`), provided the administrator certificate (`administrator.pfx`), and requested a **Kerberos Ticket Granting Ticket (TGT)**. The request was successful, and the tool saved the administrator’s TGT into a cache file (`administrator.ccache`).

Certipy then attempted to retrieve the NTLM hash for the administrator account. This process worked, and I successfully obtained the administrator’s NT hash.

At this stage, I had both a valid Kerberos ticket and the NTLM hash for the domain administrator, confirming full compromise of the domain with the highest level of privileges.

<img width="1824" height="604" alt="image" src="https://github.com/user-attachments/assets/4aca1fff-2b87-4afa-a1d8-bdc1b817cf04" />


fter obtaining the NTLM hash for the Administrator account, I used **Evil-WinRM** to establish a remote session on the target system with full administrative privileges. I supplied the machine’s IP address (`10.10.11.69`), the username (`Administrator`), and the Administrator NTLM hash I had extracted earlier. The authentication was successful, and I gained an interactive PowerShell session as the domain Administrator.

Once inside, I navigated to the Administrator’s Desktop directory. There, I confirmed the presence of the `root.txt` file, which validated that I had achieved complete system compromise and domain administrator–level access.

<img width="1988" height="782" alt="image" src="https://github.com/user-attachments/assets/6bcae285-0f88-49b0-b1b4-d5cd3fe153c1" />
