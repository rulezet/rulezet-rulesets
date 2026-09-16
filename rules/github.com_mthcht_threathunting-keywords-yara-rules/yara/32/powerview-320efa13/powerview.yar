rule powerview
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGet\-DomainController\s\|\sselect\sName\,OSversion\,IPAddress\s\|fl/ nocase ascii wide
                        $string2 = /\sGet\-DomainGPO\s\-Identity\s\\"\{AB306569\-220D\-43FF\-B03B\-83E8F4EF8081\}\\"/ nocase ascii wide
                        $string3 = " Invoke-ShareFinder -CheckShareAccess" nocase ascii wide
                        $string4 = /\spowerview\.py/ nocase ascii wide
                        $string5 = /\.powerview\.ldap_session/ nocase ascii wide
                        $string6 = /\/\.powerview\/\.powerview_history/
                        $string7 = /\/\.powerview\/logs/
                        $string8 = /\/powerview\.py/ nocase ascii wide
                        $string9 = /\/powerview\.py\.git/ nocase ascii wide
                        $string10 = /\[Find\-DomainShare\]\sEnumerating\sserver\s/ nocase ascii wide
                        $string11 = /\\ldap_shell\.cmd/ nocase ascii wide
                        $string12 = /\\PowerView\.Log/ nocase ascii wide
                        $string13 = /\\powerview\.py/ nocase ascii wide
                        $string14 = "507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87" nocase ascii wide
                        $string15 = "848D3E89D46E285D5BCFA7FD13E805ABCB8BAE926F7F1B40092EA56F4A025CAA" nocase ascii wide
                        $string16 = "8be1679cd0a2661629259d0011fe9a3bc3e7270801d97fc154577b10b85494fb" nocase ascii wide
                        $string17 = "903fa9aeb7419d81f75d5a5a226623c5ec63a52b6da020135b864cd7d92284c9" nocase ascii wide
                        $string18 = "9877ed9aec8766036bb9dd702e41433916a6d6c886ff55eea07fce92bcbf6b29" nocase ascii wide
                        $string19 = /Add\-ObjectAcl\s\-TargetADSprefix\s\'CN\=AdminSDHolder.{0,1000}CN\=System\'\s\-PrincipalSamAccountName\s.{0,1000}\s\-Rights\sAll/ nocase ascii wide
                        $string20 = /aniqfakhrul\/powerview\.py/ nocase ascii wide
                        $string21 = /aniqfakhrull\@gmail\.com/ nocase ascii wide
                        $string22 = "b43587da7d68a081ddc3a46993f797782e813ed07ccc5f33fe37b14a653ccfed" nocase ascii wide
                        $string23 = "c2268ac17f1df0139ec5aa11da1ae6b8bef2ad3588f31d8e62c85a55cf85b073" nocase ascii wide
                        $string24 = /curl\s\-L\spowerview\.sh\s/
                        $string25 = "d56e0de10ba38b39604171a2cfb22ff4cd6dffcd5f7646fb01a1715d39c522b6" nocase ascii wide
                        $string26 = "d64995d25e55ebb524c83a516e8996cc3e3dd8cb03b7332f8ad95a5c775385b0" nocase ascii wide
                        $string27 = "Export-PowerViewCSV" nocase ascii wide
                        $string28 = "Find-GPOComputerAdmin" nocase ascii wide
                        $string29 = "Find-InterestingDomainAcl" nocase ascii wide
                        $string30 = "Find-InterestingDomainShareFile" nocase ascii wide
                        $string31 = "Find-InterestingFile" nocase ascii wide
                        $string32 = "Find-LocalAdminAccess" nocase ascii wide
                        $string33 = /Get\-DomainComputer\s\-Ping\s\s\|\sselect\sname\,logoncount\,descreption\,operatingsystem/ nocase ascii wide
                        $string34 = "Get-DomainGPOUserLocalGroupMapping" nocase ascii wide
                        $string35 = /Get\-DomainGroupMember\s\-Identity\s\\"Domain\sAdmins\\"\s\|/ nocase ascii wide
                        $string36 = "Get-DomainGroupMemberDeleted" nocase ascii wide
                        $string37 = "Get-DomainSPNTicket" nocase ascii wide
                        $string38 = "Get-DomainUser -PreauthNotRequired" nocase ascii wide
                        $string39 = /Get\-DomainUser\s\-SPN\s\|\sselect\ssamaccountname\,serviceprincipalname/ nocase ascii wide
                        $string40 = /Get\-LastLoggedOn\s\?ComputerName\s/ nocase ascii wide
                        $string41 = "Get-LocalGroupMember -Group Administrators" nocase ascii wide
                        $string42 = "Get-LoggedonLocal -ComputerName " nocase ascii wide
                        $string43 = "Get-NetLocalGroupMember" nocase ascii wide
                        $string44 = "Get-NetLoggedon" nocase ascii wide
                        $string45 = "Get-NetRDPSession" nocase ascii wide
                        $string46 = "Get-RegLoggedOn" nocase ascii wide
                        $string47 = "Get-WMIRegCachedRDPConnection" nocase ascii wide
                        $string48 = "Get-WMIRegLastLoggedOn" nocase ascii wide
                        $string49 = "Get-WMIRegMountedDrive" nocase ascii wide
                        $string50 = "Invoke-EnumerateLocalAdmin" nocase ascii wide
                        $string51 = "Invoke-Kerberoast" nocase ascii wide
                        $string52 = "Invoke-Kerberoast" nocase ascii wide
                        $string53 = "Invoke-RevertToSelf" nocase ascii wide
                        $string54 = /Invoke\-UserImpersonation\s\-Credential\s.{0,1000}\s\-Quiet/ nocase ascii wide
                        $string55 = "Invoke-UserImpersonation" nocase ascii wide
                        $string56 = /kerberoast\.py/ nocase ascii wide
                        $string57 = /ldap3\.git\@powerview\.py/ nocase ascii wide
                        $string58 = /ldapattack\.py/ nocase ascii wide
                        $string59 = /PetitPotam\.py/ nocase ascii wide
                        $string60 = "pip3 install powerview " nocase ascii wide
                        $string61 = /PowerView\.ps1/ nocase ascii wide
                        $string62 = /PowerView\.ShareInfo/ nocase ascii wide
                        $string63 = /PowerView\.SPNTicket/ nocase ascii wide
                        $string64 = /PowerView\-2\.0\-tricks\.ps1/ nocase ascii wide
                        $string65 = /System\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken\s\-ArgumentList\s\$UserSPN/ nocase ascii wide

    condition:
        any of them
}