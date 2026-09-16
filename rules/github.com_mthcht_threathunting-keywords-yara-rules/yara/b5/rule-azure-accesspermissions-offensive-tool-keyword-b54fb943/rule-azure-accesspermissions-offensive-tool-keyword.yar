rule rule_Azure_AccessPermissions_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azure-AccessPermissions' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure-AccessPermissions"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Azure_AccessPermissions_offensive_tool_keyword = /\/Azure\-AccessPermissions\.git/ nocase ascii wide
                        $string2_Azure_AccessPermissions_offensive_tool_keyword = "AAP-AddToHighPrivilegePrincipalMap" nocase ascii wide
                        $string3_Azure_AccessPermissions_offensive_tool_keyword = "AAP-CheckIfMemberOfPrivilegedDirectoryRole" nocase ascii wide
                        $string4_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID" nocase ascii wide
                        $string5_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayHighPrivilegePrincipalMap" nocase ascii wide
                        $string6_Azure_AccessPermissions_offensive_tool_keyword = "AAP-DisplayNonHighPrivilegedRoleAssignments" nocase ascii wide
                        $string7_Azure_AccessPermissions_offensive_tool_keyword = "AAP-GetHighPrivilegedDirectoryRoleTemplateMap" nocase ascii wide
                        $string8_Azure_AccessPermissions_offensive_tool_keyword = /Azure\-AccessPermissions\.ps1/ nocase ascii wide
                        $string9_Azure_AccessPermissions_offensive_tool_keyword = "Azure-AccessPermissions-master" nocase ascii wide
                        $string10_Azure_AccessPermissions_offensive_tool_keyword = "csandker/Azure-AccessPermissions" nocase ascii wide
                        $string11_Azure_AccessPermissions_offensive_tool_keyword = "Enumerate-AllHighPrivilegePrincipals" nocase ascii wide
                        $string12_Azure_AccessPermissions_offensive_tool_keyword = "Enumerate-MFAStatusOfHighPrivilegePrincipals" nocase ascii wide
                        $string13_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllGroups" nocase ascii wide
                        $string14_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllServicePrincipals" nocase ascii wide
                        $string15_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForAllUsers" nocase ascii wide
                        $string16_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string17_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
                        $string18_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForGroup" nocase ascii wide
                        $string19_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForServicePrincipal" nocase ascii wide
                        $string20_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AccessCheckForUser" nocase ascii wide
                        $string21_Azure_AccessPermissions_offensive_tool_keyword = "Invoke-AllAccessChecks" nocase ascii wide
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