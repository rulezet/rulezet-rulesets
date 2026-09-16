rule rule_ptunnel_ng_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ptunnel-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ptunnel-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ptunnel_ng_offensive_tool_keyword = " ptunnel-ng" nocase ascii wide
                        $string2_ptunnel_ng_offensive_tool_keyword = "/ptunnel-ng" nocase ascii wide
                        $string3_ptunnel_ng_offensive_tool_keyword = "/var/lib/ptunnel"
                        $string4_ptunnel_ng_offensive_tool_keyword = /nc\s127\.0\.0\.1\s4000/ nocase ascii wide
                        $string5_ptunnel_ng_offensive_tool_keyword = /new\ssession\sto\s127\.0\.0\.1\:3000/ nocase ascii wide
                        $string6_ptunnel_ng_offensive_tool_keyword = /ptunnel\-client\.log/ nocase ascii wide
                        $string7_ptunnel_ng_offensive_tool_keyword = "ptunnel-data-recv" nocase ascii wide
                        $string8_ptunnel_ng_offensive_tool_keyword = "ptunnel-data-send" nocase ascii wide
                        $string9_ptunnel_ng_offensive_tool_keyword = "ptunnel-master" nocase ascii wide
                        $string10_ptunnel_ng_offensive_tool_keyword = "ptunnel-ng " nocase ascii wide
                        $string11_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\.conf/ nocase ascii wide
                        $string12_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\.git/ nocase ascii wide
                        $string13_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\.service/ nocase ascii wide
                        $string14_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\.te/ nocase ascii wide
                        $string15_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\-x64\.exe/ nocase ascii wide
                        $string16_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\-x64\-dbg\.exe/ nocase ascii wide
                        $string17_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\-x86\.exe/ nocase ascii wide
                        $string18_ptunnel_ng_offensive_tool_keyword = /ptunnel\-ng\-x86\-dbg\.exe/ nocase ascii wide
                        $string19_ptunnel_ng_offensive_tool_keyword = /ptunnel\-server\.log/ nocase ascii wide
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