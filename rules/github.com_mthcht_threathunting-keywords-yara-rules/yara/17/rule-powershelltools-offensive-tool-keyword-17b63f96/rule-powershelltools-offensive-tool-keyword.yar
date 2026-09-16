rule rule_PowershellTools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowershellTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowershellTools_offensive_tool_keyword = /\sPowerTools\.ps1/ nocase ascii wide
                        $string2_PowershellTools_offensive_tool_keyword = /\sQuickViewAD\.ps1/ nocase ascii wide
                        $string3_PowershellTools_offensive_tool_keyword = /\.exe\sasktgs\s\/ticket\:B64_TGT\s\/service\:/ nocase ascii wide
                        $string4_PowershellTools_offensive_tool_keyword = /\.exe\ssilver\s\/sids\:.{0,100}\/target\:/ nocase ascii wide
                        $string5_PowershellTools_offensive_tool_keyword = /\/PowershellTools\.git/ nocase ascii wide
                        $string6_PowershellTools_offensive_tool_keyword = /\/PowerTools\.ps1/ nocase ascii wide
                        $string7_PowershellTools_offensive_tool_keyword = /\/QuickViewAD\.ps1/ nocase ascii wide
                        $string8_PowershellTools_offensive_tool_keyword = /\\PowerTools\.ps1/ nocase ascii wide
                        $string9_PowershellTools_offensive_tool_keyword = /\\QuickViewAD\.ps1/ nocase ascii wide
                        $string10_PowershellTools_offensive_tool_keyword = /C\:\\Temp\\.{0,100}\-.{0,100}\.kirbi/ nocase ascii wide
                        $string11_PowershellTools_offensive_tool_keyword = "Find-ADInterestingACL " nocase ascii wide
                        $string12_PowershellTools_offensive_tool_keyword = /Find\-ADInterestingACL\.ps1/ nocase ascii wide
                        $string13_PowershellTools_offensive_tool_keyword = "Get-NestedGroupMembership " nocase ascii wide
                        $string14_PowershellTools_offensive_tool_keyword = /Get\-NestedGroupMembership\.ps1/ nocase ascii wide
                        $string15_PowershellTools_offensive_tool_keyword = /Get\-TrustTicket\.ps1/ nocase ascii wide
                        $string16_PowershellTools_offensive_tool_keyword = "gustanini/PowershellTools" nocase ascii wide
                        $string17_PowershellTools_offensive_tool_keyword = "Invoke-AccessCheck -PSRemoting" nocase ascii wide
                        $string18_PowershellTools_offensive_tool_keyword = "Invoke-AccessCheck -SMB" nocase ascii wide
                        $string19_PowershellTools_offensive_tool_keyword = /Invoke\-AccessCheck\.ps1/ nocase ascii wide
                        $string20_PowershellTools_offensive_tool_keyword = "kerberos::golden /service:" nocase ascii wide
                        $string21_PowershellTools_offensive_tool_keyword = /PowershellTools\-main\.zip/ nocase ascii wide
                        $string22_PowershellTools_offensive_tool_keyword = "Set-MacroSecurityOff " nocase ascii wide
                        $string23_PowershellTools_offensive_tool_keyword = /Set\-MacroSecurityOff\.ps1/ nocase ascii wide
                        $string24_PowershellTools_offensive_tool_keyword = "tgs::ask /tgt:" nocase ascii wide
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