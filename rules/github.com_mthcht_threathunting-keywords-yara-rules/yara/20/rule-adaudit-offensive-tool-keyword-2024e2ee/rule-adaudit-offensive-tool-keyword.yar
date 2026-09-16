rule rule_adaudit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adaudit_offensive_tool_keyword = /\sADAudit\.ps1/ nocase ascii wide
                        $string2_adaudit_offensive_tool_keyword = /\/adaudit\.git/ nocase ascii wide
                        $string3_adaudit_offensive_tool_keyword = /\/ADAudit\.ps1/ nocase ascii wide
                        $string4_adaudit_offensive_tool_keyword = /\[\!\]\sYou\shave\sDCs\swith\sRC4\sor\sDES\sallowed\sfor\sKerberos\!\!\!/ nocase ascii wide
                        $string5_adaudit_offensive_tool_keyword = /\\accounts_passdontexpire\.txt/ nocase ascii wide
                        $string6_adaudit_offensive_tool_keyword = /\\ADAudit\.ps1/ nocase ascii wide
                        $string7_adaudit_offensive_tool_keyword = /\\dangerousACL_Computer\.txt/ nocase ascii wide
                        $string8_adaudit_offensive_tool_keyword = /\\dangerousACL_Groups\.txt/ nocase ascii wide
                        $string9_adaudit_offensive_tool_keyword = /\\dcs_weak_kerberos_ciphersuite\.txt/ nocase ascii wide
                        $string10_adaudit_offensive_tool_keyword = /\\domain_admins\.txt/ nocase ascii wide
                        $string11_adaudit_offensive_tool_keyword = /\\enterprise_admins\.txt/ nocase ascii wide
                        $string12_adaudit_offensive_tool_keyword = /\]\sCheck\sfor\sADCS\sVulnerabilities/ nocase ascii wide
                        $string13_adaudit_offensive_tool_keyword = "5f871566a9113e31357e084743f12b74b7199019e66cd10847b61b5666ecf9b1" nocase ascii wide
                        $string14_adaudit_offensive_tool_keyword = "Find-DangerousACLPermissions" nocase ascii wide
                        $string15_adaudit_offensive_tool_keyword = "Get-AccountPassDontExpire" nocase ascii wide
                        $string16_adaudit_offensive_tool_keyword = "Get-ADCSVulns" nocase ascii wide
                        $string17_adaudit_offensive_tool_keyword = "Get-ADUsersWithoutPreAuth" nocase ascii wide
                        $string18_adaudit_offensive_tool_keyword = "Get-DCsNotOwnedByDA" nocase ascii wide
                        $string19_adaudit_offensive_tool_keyword = "Get-GPOEnum" nocase ascii wide
                        $string20_adaudit_offensive_tool_keyword = "Get-GPOsPerOU" nocase ascii wide
                        $string21_adaudit_offensive_tool_keyword = "Get-GPOtoFile" nocase ascii wide
                        $string22_adaudit_offensive_tool_keyword = /Get\-GPPPassword\./ nocase ascii wide
                        $string23_adaudit_offensive_tool_keyword = "Get-NTDSdit" nocase ascii wide
                        $string24_adaudit_offensive_tool_keyword = "Get-PrivilegedGroupAccounts" nocase ascii wide
                        $string25_adaudit_offensive_tool_keyword = "Get-PrivilegedGroupMembership" nocase ascii wide
                        $string26_adaudit_offensive_tool_keyword = "Kerberoast Attack - Services Configured With a Weak Password" nocase ascii wide
                        $string27_adaudit_offensive_tool_keyword = "phillips321/adaudit" nocase ascii wide
                        $string28_adaudit_offensive_tool_keyword = "Write-Nessus-Finding" nocase ascii wide
                        $string29_adaudit_offensive_tool_keyword = "Write-Nessus-Footer" nocase ascii wide
                        $string30_adaudit_offensive_tool_keyword = "Write-Nessus-Header" nocase ascii wide
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