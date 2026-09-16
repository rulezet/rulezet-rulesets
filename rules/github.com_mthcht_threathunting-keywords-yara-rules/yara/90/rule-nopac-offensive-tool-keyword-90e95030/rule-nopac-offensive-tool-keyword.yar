rule rule_noPac_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'noPac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noPac"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_noPac_offensive_tool_keyword = "/Ridter/noPac" nocase ascii wide
                        $string2_noPac_offensive_tool_keyword = /AdFind\.exe\s\-sc\sgetacls\s\-sddlfilter\s\s\s.{0,100}computer.{0,100}\s\-recmute/ nocase ascii wide
                        $string3_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-create\-child/ nocase ascii wide
                        $string4_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-dc\-host\s/ nocase ascii wide
                        $string5_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-dc\-ip\s/ nocase ascii wide
                        $string6_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-domain\-netbios/ nocase ascii wide
                        $string7_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-dump/ nocase ascii wide
                        $string8_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-hashes\s/ nocase ascii wide
                        $string9_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-\-impersonate\s/ nocase ascii wide
                        $string10_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-just\-dc\-ntlm/ nocase ascii wide
                        $string11_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-just\-dc\-user\s/ nocase ascii wide
                        $string12_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-new\-name\s/ nocase ascii wide
                        $string13_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-no\-add\s/ nocase ascii wide
                        $string14_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-pwd\-last\-set/ nocase ascii wide
                        $string15_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-service\-name\s/ nocase ascii wide
                        $string16_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-shell/ nocase ascii wide
                        $string17_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-shell\-type\s/ nocase ascii wide
                        $string18_noPac_offensive_tool_keyword = /noPac\..{0,100}\s\-use\-ldap/ nocase ascii wide
                        $string19_noPac_offensive_tool_keyword = /noPac\.py/ nocase ascii wide
                        $string20_noPac_offensive_tool_keyword = /python\snoPac\./ nocase ascii wide
                        $string21_noPac_offensive_tool_keyword = "Ridter/noPac" nocase ascii wide
                        $string22_noPac_offensive_tool_keyword = /S4U2self\.py/ nocase ascii wide
                        $string23_noPac_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide
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