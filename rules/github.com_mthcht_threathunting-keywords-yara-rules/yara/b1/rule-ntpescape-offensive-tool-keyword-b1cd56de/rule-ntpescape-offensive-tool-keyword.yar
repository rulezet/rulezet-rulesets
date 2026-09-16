rule rule_ntpescape_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntpescape' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntpescape"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntpescape_offensive_tool_keyword = /\s\|\s\.\/send\s\-d\s.{0,100}\:123\s\-tM\s0\s\-tm\s0/
                        $string2_ntpescape_offensive_tool_keyword = /\.\/recv\s\-d\s\:50001/
                        $string3_ntpescape_offensive_tool_keyword = /\.\/send\s\-d\s.{0,100}\:123\s\-f\s/
                        $string4_ntpescape_offensive_tool_keyword = /\/ntpescape\.git/ nocase ascii wide
                        $string5_ntpescape_offensive_tool_keyword = "evallen/ntpescape" nocase ascii wide
                        $string6_ntpescape_offensive_tool_keyword = /ntpescape.{0,100}recv/ nocase ascii wide
                        $string7_ntpescape_offensive_tool_keyword = /ntpescape.{0,100}send/ nocase ascii wide
                        $string8_ntpescape_offensive_tool_keyword = /ntpescape\-master\./ nocase ascii wide
                        $string9_ntpescape_offensive_tool_keyword = /sudo\s\.\/recv\s\-f\s/
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