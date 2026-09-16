rule rule_ldap_queries_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldap queries' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldap queries"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ldap_queries_greyware_tool_keyword = /\(\&\(\&\(objectCategory\=person\)\(objectClass\=user\)\)\(\|\(description\=.{0,100}pass.{0,100}\)\(comment\=.{0,100}pass.{0,100}\)\)\)/ nocase ascii wide
                        $string2_ldap_queries_greyware_tool_keyword = /\(\&\(objectCategory\=computer\)\(msDS\-isRODC\=TRUE\)\)/ nocase ascii wide
                        $string3_ldap_queries_greyware_tool_keyword = /\(\&\(objectCategory\=computer\)\(ms\-MCS\-AdmPwd\=.{0,100}\)\(sAMAccountName\=\\"\s\+\starget\s\+\s\\"\)\)/ nocase ascii wide
                        $string4_ldap_queries_greyware_tool_keyword = /\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=65536\)\(memberOf\=CN\=Administrators/ nocase ascii wide
                        $string5_ldap_queries_greyware_tool_keyword = /\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=65536\)/ nocase ascii wide
                        $string6_ldap_queries_greyware_tool_keyword = /\(\&\(objectClass\=group\)\(managedBy\=.{0,100}\)\(groupType\:1\.2\.840\.113556\.1\.4\.803\:\=2147483648\)\)/ nocase ascii wide
                        $string7_ldap_queries_greyware_tool_keyword = /\(\&\(objectclass\=group\)\(samaccountname\=.{0,100}domain\sadmins.{0,100}\)\)/ nocase ascii wide
                        $string8_ldap_queries_greyware_tool_keyword = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,100}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(\!msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.804\:\=24\)\)/ nocase ascii wide
                        $string9_ldap_queries_greyware_tool_keyword = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,100}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.804\:\=24\)\)/ nocase ascii wide
                        $string10_ldap_queries_greyware_tool_keyword = /\(\&\(samAccountType\=805306368\)\(servicePrincipalName\=.{0,100}\)\(\!samAccountName\=krbtgt\)\(\!\(UserAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)/ nocase ascii wide
                        $string11_ldap_queries_greyware_tool_keyword = /\(\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(\!\(primaryGroupID\=516\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string12_ldap_queries_greyware_tool_keyword = /\(\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=8192\)\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string13_ldap_queries_greyware_tool_keyword = /\(\[adsisearcher\]\'\(\&\(objectCategory\=user\)\(\!\(samAccountName\=krbtgt\)\(servicePrincipalName\=.{0,100}\)\)\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string14_ldap_queries_greyware_tool_keyword = /\(\[adsisearcher\]\'\(adminCount\=1\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string15_ldap_queries_greyware_tool_keyword = /\(\[DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\)\.Domains/ nocase ascii wide
                        $string16_ldap_queries_greyware_tool_keyword = /\(\[DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\)\.Sites\s\|\s/ nocase ascii wide
                        $string17_ldap_queries_greyware_tool_keyword = /\(\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\)\.FindAllDomainControllers\(\)\s\|\sSelect\-Object\s\-Property\s/ nocase ascii wide
                        $string18_ldap_queries_greyware_tool_keyword = /\(\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\)\.GetAllTrustRelationships\(\)/ nocase ascii wide
                        $string19_ldap_queries_greyware_tool_keyword = /\(Get\-ADForest\)\.Domains\s\|\s\%\{\sGet\-ADDomainController\s\-Filter\s.{0,100}\s\-Server\s\$_\s\}/ nocase ascii wide
                        $string20_ldap_queries_greyware_tool_keyword = /\(msds\-supportedencryptiontypes\=0\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.803\:\=4\)\)\)/ nocase ascii wide
                        $string21_ldap_queries_greyware_tool_keyword = /\(objectCategory\=person\)\(objectClass\=user\)\(serviceAccount\=TRUE\)/ nocase ascii wide
                        $string22_ldap_queries_greyware_tool_keyword = /\(objectclass\=group\)\(samaccountname\=domain\sadmins\)/ nocase ascii wide
                        $string23_ldap_queries_greyware_tool_keyword = /\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)/ nocase ascii wide
                        $string24_ldap_queries_greyware_tool_keyword = /\[ADSI\].{0,100}\s\|\sSelect\-Object\s\-Property\s.{0,100}lockoutDuration/ nocase ascii wide
                        $string25_ldap_queries_greyware_tool_keyword = /\[ADSI\].{0,100}\s\|\sSelect\-Object\s\-Property\s.{0,100}lockoutThreshold/ nocase ascii wide
                        $string26_ldap_queries_greyware_tool_keyword = /\[ADSI\].{0,100}\s\|\sSelect\-Object\s\-Property\s.{0,100}minPwdLength/ nocase ascii wide
                        $string27_ldap_queries_greyware_tool_keyword = /\[ADSI\].{0,100}LDAP\:\/\/CN\=Domain\sAdmins.{0,100}\|\sForEach\-Object\s\{\[adsi\]\\"LDAP\:\/\/\$_\\"\}\;\s.{0,100}\.distinguishedname/ nocase ascii wide
                        $string28_ldap_queries_greyware_tool_keyword = /\[ADSI\].{0,100}LDAP\:\/\/dc\=.{0,100}\s\|\sSelect\s\-Property\spwdProperties/ nocase ascii wide
                        $string29_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)\\"\;\s\$users\s\=\s\$searchUsers\.FindAll\(\)\;\s\$userProps\s\=\s\$users\.Properties\;\s\$userProps\s\|\sWhere\-Object\s\{\$_\.description\}/ nocase ascii wide
                        $string30_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\\"/ nocase ascii wide
                        $string31_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2560\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)\\"/ nocase ascii wide
                        $string32_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\\"\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\)/ nocase ascii wide
                        $string33_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\'\(\&\(objectCategory\=computer\)\(primaryGroupID\=516\)\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string34_ldap_queries_greyware_tool_keyword = /\[adsisearcher\]\'\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32\)\)\'\)\.FindAll\(\)/ nocase ascii wide
                        $string35_ldap_queries_greyware_tool_keyword = /\[adsisearcher\].{0,100}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=66048\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)/ nocase ascii wide
                        $string36_ldap_queries_greyware_tool_keyword = /\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\.DomainControllers/ nocase ascii wide
                        $string37_ldap_queries_greyware_tool_keyword = /\[System\.DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\.GlobalCatalogs/ nocase ascii wide
                        $string38_ldap_queries_greyware_tool_keyword = /\[System\.DirectoryServices\.ActiveDirectory\.Forest\]\:\:GetCurrentForest\(\)\.RootDomain\.PDCRoleOwner\.Name/ nocase ascii wide
                        $string39_ldap_queries_greyware_tool_keyword = /get\-ADComputer\s\-filter\s\{\sPrimaryGroupID\s\-eq\s\\"516\\"\s\}\s\-properties\sPrimaryGroupID/ nocase ascii wide
                        $string40_ldap_queries_greyware_tool_keyword = /Get\-ADUser\s\-filter\s.{0,100}\s\-Properties\sSamAccountName\,\sPasswordNotRequired\s\|\swhere\s\{\s\$_\.passwordnotrequired\s\-eq\s\\"true\\"\s\}\s\|\swhere\s\{\$_\.enabled\s\-eq\s\\"true\\"\}/ nocase ascii wide
                        $string41_ldap_queries_greyware_tool_keyword = /Get\-ADUser\s\-properties\s.{0,100}\s\-filter\s\{\(lastlogondate\s\-notlike\s\\".{0,100}\\"\s\-OR\slastlogondate\s\-le\s\$90days\)\s\-AND\s\(passwordlastset\s\-le\s\$90days\)\s\-AND\s\(enabled\s\-eq\s\$True\)\s\-and\s\(PasswordNeverExpires\s\-eq\s\$false\)\s\-and\s\(whencreated\s\-le\s\$90days\)\}/ nocase ascii wide
                        $string42_ldap_queries_greyware_tool_keyword = /powershell.{0,100}\[adsisearcher\].{0,100}\(objectcategory\=group\).{0,100}findAll\(\)/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}