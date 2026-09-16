rule rule_LTProxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LTProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LTProxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_LTProxy_greyware_tool_keyword = /\/\.ltproxy\.yml/
                        $string2_LTProxy_greyware_tool_keyword = /\/etc\/ltproxy\.yml/
                        $string3_LTProxy_greyware_tool_keyword = /\/LTProxy\.git/
                        $string4_LTProxy_greyware_tool_keyword = /\/tmp\/\.ltproxy_proxychains_/
                        $string5_LTProxy_greyware_tool_keyword = /\\LTProxy\-main/
                        $string6_LTProxy_greyware_tool_keyword = "ac5f344727467b6ad9743b8ffa2646ed73180dbdb97224feec6c54c5160a1984"
                        $string7_LTProxy_greyware_tool_keyword = /ipt2socks\s\-R\s\-n\s9999\s\-j\s50\s\-u\s.{0,100}\s\-s\s.{0,100}\s\-l\s/
                        $string8_LTProxy_greyware_tool_keyword = "L-codes/LTProxy"
                        $string9_LTProxy_greyware_tool_keyword = "ltproxy restart"
                        $string10_LTProxy_greyware_tool_keyword = "ltproxy start"
                        $string11_LTProxy_greyware_tool_keyword = "ltproxy stop"
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