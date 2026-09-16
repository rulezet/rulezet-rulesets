rule rule_powerview_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_powerview_offensive_tool_keyword = /\sGet\-DomainController\s\|\sselect\sName\,OSversion\,IPAddress\s\|fl/ nocase ascii wide
                        $string2_powerview_offensive_tool_keyword = /\sGet\-DomainGPO\s\-Identity\s\\"\{AB306569\-220D\-43FF\-B03B\-83E8F4EF8081\}\\"/ nocase ascii wide
                        $string3_powerview_offensive_tool_keyword = " Invoke-ShareFinder -CheckShareAccess" nocase ascii wide
                        $string4_powerview_offensive_tool_keyword = /\spowerview\.py/ nocase ascii wide
                        $string5_powerview_offensive_tool_keyword = /\.powerview\.ldap_session/ nocase ascii wide
                        $string6_powerview_offensive_tool_keyword = /\/\.powerview\/\.powerview_history/
                        $string7_powerview_offensive_tool_keyword = /\/\.powerview\/logs/
                        $string8_powerview_offensive_tool_keyword = /\/powerview\.py/ nocase ascii wide
                        $string9_powerview_offensive_tool_keyword = /\/powerview\.py\.git/ nocase ascii wide
                        $string10_powerview_offensive_tool_keyword = /\[Find\-DomainShare\]\sEnumerating\sserver\s/ nocase ascii wide
                        $string11_powerview_offensive_tool_keyword = /\\ldap_shell\.cmd/ nocase ascii wide
                        $string12_powerview_offensive_tool_keyword = /\\PowerView\.Log/ nocase ascii wide
                        $string13_powerview_offensive_tool_keyword = /\\powerview\.py/ nocase ascii wide
                        $string14_powerview_offensive_tool_keyword = "507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87" nocase ascii wide
                        $string15_powerview_offensive_tool_keyword = "848D3E89D46E285D5BCFA7FD13E805ABCB8BAE926F7F1B40092EA56F4A025CAA" nocase ascii wide
                        $string16_powerview_offensive_tool_keyword = "8be1679cd0a2661629259d0011fe9a3bc3e7270801d97fc154577b10b85494fb" nocase ascii wide
                        $string17_powerview_offensive_tool_keyword = "903fa9aeb7419d81f75d5a5a226623c5ec63a52b6da020135b864cd7d92284c9" nocase ascii wide
                        $string18_powerview_offensive_tool_keyword = "9877ed9aec8766036bb9dd702e41433916a6d6c886ff55eea07fce92bcbf6b29" nocase ascii wide
                        $string19_powerview_offensive_tool_keyword = /Add\-ObjectAcl\s\-TargetADSprefix\s\'CN\=AdminSDHolder.{0,1000}CN\=System\'\s\-PrincipalSamAccountName\s.{0,1000}\s\-Rights\sAll/ nocase ascii wide
                        $string20_powerview_offensive_tool_keyword = /aniqfakhrul\/powerview\.py/ nocase ascii wide
                        $string21_powerview_offensive_tool_keyword = /aniqfakhrull\@gmail\.com/ nocase ascii wide
                        $string22_powerview_offensive_tool_keyword = "b43587da7d68a081ddc3a46993f797782e813ed07ccc5f33fe37b14a653ccfed" nocase ascii wide
                        $string23_powerview_offensive_tool_keyword = "c2268ac17f1df0139ec5aa11da1ae6b8bef2ad3588f31d8e62c85a55cf85b073" nocase ascii wide
                        $string24_powerview_offensive_tool_keyword = /curl\s\-L\spowerview\.sh\s/
                        $string25_powerview_offensive_tool_keyword = "d56e0de10ba38b39604171a2cfb22ff4cd6dffcd5f7646fb01a1715d39c522b6" nocase ascii wide
                        $string26_powerview_offensive_tool_keyword = "d64995d25e55ebb524c83a516e8996cc3e3dd8cb03b7332f8ad95a5c775385b0" nocase ascii wide
                        $string27_powerview_offensive_tool_keyword = "Export-PowerViewCSV" nocase ascii wide
                        $string28_powerview_offensive_tool_keyword = "Find-GPOComputerAdmin" nocase ascii wide
                        $string29_powerview_offensive_tool_keyword = "Find-InterestingDomainAcl" nocase ascii wide
                        $string30_powerview_offensive_tool_keyword = "Find-InterestingDomainShareFile" nocase ascii wide
                        $string31_powerview_offensive_tool_keyword = "Find-InterestingFile" nocase ascii wide
                        $string32_powerview_offensive_tool_keyword = "Find-LocalAdminAccess" nocase ascii wide
                        $string33_powerview_offensive_tool_keyword = /Get\-DomainComputer\s\-Ping\s\s\|\sselect\sname\,logoncount\,descreption\,operatingsystem/ nocase ascii wide
                        $string34_powerview_offensive_tool_keyword = "Get-DomainGPOUserLocalGroupMapping" nocase ascii wide
                        $string35_powerview_offensive_tool_keyword = /Get\-DomainGroupMember\s\-Identity\s\\"Domain\sAdmins\\"\s\|/ nocase ascii wide
                        $string36_powerview_offensive_tool_keyword = "Get-DomainGroupMemberDeleted" nocase ascii wide
                        $string37_powerview_offensive_tool_keyword = "Get-DomainSPNTicket" nocase ascii wide
                        $string38_powerview_offensive_tool_keyword = "Get-DomainUser -PreauthNotRequired" nocase ascii wide
                        $string39_powerview_offensive_tool_keyword = /Get\-DomainUser\s\-SPN\s\|\sselect\ssamaccountname\,serviceprincipalname/ nocase ascii wide
                        $string40_powerview_offensive_tool_keyword = /Get\-LastLoggedOn\s\?ComputerName\s/ nocase ascii wide
                        $string41_powerview_offensive_tool_keyword = "Get-LocalGroupMember -Group Administrators" nocase ascii wide
                        $string42_powerview_offensive_tool_keyword = "Get-LoggedonLocal -ComputerName " nocase ascii wide
                        $string43_powerview_offensive_tool_keyword = "Get-NetLocalGroupMember" nocase ascii wide
                        $string44_powerview_offensive_tool_keyword = "Get-NetLoggedon" nocase ascii wide
                        $string45_powerview_offensive_tool_keyword = "Get-NetRDPSession" nocase ascii wide
                        $string46_powerview_offensive_tool_keyword = "Get-RegLoggedOn" nocase ascii wide
                        $string47_powerview_offensive_tool_keyword = "Get-WMIRegCachedRDPConnection" nocase ascii wide
                        $string48_powerview_offensive_tool_keyword = "Get-WMIRegLastLoggedOn" nocase ascii wide
                        $string49_powerview_offensive_tool_keyword = "Get-WMIRegMountedDrive" nocase ascii wide
                        $string50_powerview_offensive_tool_keyword = "Invoke-EnumerateLocalAdmin" nocase ascii wide
                        $string51_powerview_offensive_tool_keyword = "Invoke-Kerberoast" nocase ascii wide
                        $string52_powerview_offensive_tool_keyword = "Invoke-Kerberoast" nocase ascii wide
                        $string53_powerview_offensive_tool_keyword = "Invoke-RevertToSelf" nocase ascii wide
                        $string54_powerview_offensive_tool_keyword = /Invoke\-UserImpersonation\s\-Credential\s.{0,1000}\s\-Quiet/ nocase ascii wide
                        $string55_powerview_offensive_tool_keyword = "Invoke-UserImpersonation" nocase ascii wide
                        $string56_powerview_offensive_tool_keyword = /kerberoast\.py/ nocase ascii wide
                        $string57_powerview_offensive_tool_keyword = /ldap3\.git\@powerview\.py/ nocase ascii wide
                        $string58_powerview_offensive_tool_keyword = /ldapattack\.py/ nocase ascii wide
                        $string59_powerview_offensive_tool_keyword = /PetitPotam\.py/ nocase ascii wide
                        $string60_powerview_offensive_tool_keyword = "pip3 install powerview " nocase ascii wide
                        $string61_powerview_offensive_tool_keyword = /PowerView\.ps1/ nocase ascii wide
                        $string62_powerview_offensive_tool_keyword = /PowerView\.ShareInfo/ nocase ascii wide
                        $string63_powerview_offensive_tool_keyword = /PowerView\.SPNTicket/ nocase ascii wide
                        $string64_powerview_offensive_tool_keyword = /PowerView\-2\.0\-tricks\.ps1/ nocase ascii wide
                        $string65_powerview_offensive_tool_keyword = /System\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken\s\-ArgumentList\s\$UserSPN/ nocase ascii wide

    condition:
        any of them
}