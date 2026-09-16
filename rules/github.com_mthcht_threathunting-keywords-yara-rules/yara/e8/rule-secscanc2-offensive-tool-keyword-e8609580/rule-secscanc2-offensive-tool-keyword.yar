rule rule_SecScanC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SecScanC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecScanC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SecScanC2_offensive_tool_keyword = /\/listProxyPool\?k\=/ nocase ascii wide
                        $string2_SecScanC2_offensive_tool_keyword = /\/SecScanC2\.git/ nocase ascii wide
                        $string3_SecScanC2_offensive_tool_keyword = /\/shell\?k\=.{0,100}\&ip\=.{0,100}\&cmd\=/ nocase ascii wide
                        $string4_SecScanC2_offensive_tool_keyword = /\/startProxyPool\?k\=.{0,100}\&random\=n\&number\=2\&ip\=/ nocase ascii wide
                        $string5_SecScanC2_offensive_tool_keyword = /\/startProxyPool\?k\=.{0,100}\&random\=y\&number\=2/ nocase ascii wide
                        $string6_SecScanC2_offensive_tool_keyword = "AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363" nocase ascii wide
                        $string7_SecScanC2_offensive_tool_keyword = "SecScanC2_admin " nocase ascii wide
                        $string8_SecScanC2_offensive_tool_keyword = "SecScanC2_admin_" nocase ascii wide
                        $string9_SecScanC2_offensive_tool_keyword = "SecScanC2_node " nocase ascii wide
                        $string10_SecScanC2_offensive_tool_keyword = "SecScanC2_node_" nocase ascii wide
                        $string11_SecScanC2_offensive_tool_keyword = "SecScanC2-main" nocase ascii wide
                        $string12_SecScanC2_offensive_tool_keyword = "T1esh0u/SecScanC2" nocase ascii wide
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