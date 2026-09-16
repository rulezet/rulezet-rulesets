rule rule_Offensive_Netsh_Helper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Netsh-Helper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Netsh-Helper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Offensive_Netsh_Helper_offensive_tool_keyword = /\/Offensive\-Netsh\-Helper\.git/ nocase ascii wide
                        $string2_Offensive_Netsh_Helper_offensive_tool_keyword = /\\netshlep\.cpp/ nocase ascii wide
                        $string3_Offensive_Netsh_Helper_offensive_tool_keyword = /\\Offensive\-Netsh\-Helper\\/ nocase ascii wide
                        $string4_Offensive_Netsh_Helper_offensive_tool_keyword = /\\Offensive\-Netsh\-Helper\-master/ nocase ascii wide
                        $string5_Offensive_Netsh_Helper_offensive_tool_keyword = "486d59732d2c346aa2cbaffff0d290b0e5fc0a967e0878240fd29df65525dfc8" nocase ascii wide
                        $string6_Offensive_Netsh_Helper_offensive_tool_keyword = "cwB0AGEAcgB0ACAAYwBhAGwAYwA=" nocase ascii wide
                        $string7_Offensive_Netsh_Helper_offensive_tool_keyword = /netsh\sadd\shelper\snetshBad\.DLL/ nocase ascii wide
                        $string8_Offensive_Netsh_Helper_offensive_tool_keyword = "rtcrowley/Offensive-Netsh-Helper" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}