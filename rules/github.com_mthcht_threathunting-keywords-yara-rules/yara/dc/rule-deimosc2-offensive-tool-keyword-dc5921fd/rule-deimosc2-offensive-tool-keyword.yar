rule rule_deimosc2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'deimosc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "deimosc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_deimosc2_offensive_tool_keyword = "/collection/screengrab" nocase ascii wide
                        $string2_deimosc2_offensive_tool_keyword = /\/dlls\/c2\.c/ nocase ascii wide
                        $string3_deimosc2_offensive_tool_keyword = "/gosecretsdump" nocase ascii wide
                        $string4_deimosc2_offensive_tool_keyword = "/resources/selfdestruction" nocase ascii wide
                        $string5_deimosc2_offensive_tool_keyword = "/shellinject" nocase ascii wide
                        $string6_deimosc2_offensive_tool_keyword = /\/webshells\/shell\.aspx/ nocase ascii wide
                        $string7_deimosc2_offensive_tool_keyword = /\/webshells\/shell\.php/ nocase ascii wide
                        $string8_deimosc2_offensive_tool_keyword = /\\gosecretsdump/ nocase ascii wide
                        $string9_deimosc2_offensive_tool_keyword = "00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64" nocase ascii wide
                        $string10_deimosc2_offensive_tool_keyword = "04ca7e137e1e9feead96a7df45bb67d5ab3de190" nocase ascii wide
                        $string11_deimosc2_offensive_tool_keyword = "38ea755e162c55ef70f9506dddfd01641fc838926af9c43eda652da63c67058b" nocase ascii wide
                        $string12_deimosc2_offensive_tool_keyword = "DeimosC2" nocase ascii wide
                        $string13_deimosc2_offensive_tool_keyword = /lsadump\.exe/ nocase ascii wide
                        $string14_deimosc2_offensive_tool_keyword = /minidump\.exe/ nocase ascii wide
                        $string15_deimosc2_offensive_tool_keyword = "module inject " nocase ascii wide
                        $string16_deimosc2_offensive_tool_keyword = /ntdsdump\.exe/ nocase ascii wide
                        $string17_deimosc2_offensive_tool_keyword = /samdump\.exe/ nocase ascii wide
                        $string18_deimosc2_offensive_tool_keyword = /samdump\.py/ nocase ascii wide
                        $string19_deimosc2_offensive_tool_keyword = /screengrab\.exe/ nocase ascii wide
                        $string20_deimosc2_offensive_tool_keyword = /shadowdump\./ nocase ascii wide
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