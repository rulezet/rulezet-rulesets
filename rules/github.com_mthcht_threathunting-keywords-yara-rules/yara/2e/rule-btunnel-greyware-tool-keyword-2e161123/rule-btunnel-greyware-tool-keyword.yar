rule rule_btunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'btunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_btunnel_greyware_tool_keyword = /\/\.btunnel\./
                        $string2_btunnel_greyware_tool_keyword = /\/btunnel\.exe/ nocase ascii wide
                        $string3_btunnel_greyware_tool_keyword = /\/btunnel\.log/
                        $string4_btunnel_greyware_tool_keyword = /\\\.btunnel\./ nocase ascii wide
                        $string5_btunnel_greyware_tool_keyword = /\\bored\-tunnel\-client/ nocase ascii wide
                        $string6_btunnel_greyware_tool_keyword = /\\btunnel\.exe/ nocase ascii wide
                        $string7_btunnel_greyware_tool_keyword = /\\btunnel\.log/ nocase ascii wide
                        $string8_btunnel_greyware_tool_keyword = "60e8a9e19b34ca6d9f1847504b7689b3f46b029ab07b4d13c6ccde026d78a0a4" nocase ascii wide
                        $string9_btunnel_greyware_tool_keyword = "af19236f06140b33ac3c78ae743627ba34dcd89be6d5c8dd22cac7f6eae19774" nocase ascii wide
                        $string10_btunnel_greyware_tool_keyword = /api\.btunnel\.in/ nocase ascii wide
                        $string11_btunnel_greyware_tool_keyword = /bored\-tunnel\-client_Windows_x86_64\./ nocase ascii wide
                        $string12_btunnel_greyware_tool_keyword = "btunnel domain " nocase ascii wide
                        $string13_btunnel_greyware_tool_keyword = "btunnel file " nocase ascii wide
                        $string14_btunnel_greyware_tool_keyword = "btunnel http" nocase ascii wide
                        $string15_btunnel_greyware_tool_keyword = "btunnel tcp --" nocase ascii wide
                        $string16_btunnel_greyware_tool_keyword = "btunnel tcp" nocase ascii wide
                        $string17_btunnel_greyware_tool_keyword = /btunnel\.exe\shttp/ nocase ascii wide
                        $string18_btunnel_greyware_tool_keyword = "eb1395952e6eb92d4f9a2babb56d29ef384d683387c6a990e79d5fe4ba86040f" nocase ascii wide
                        $string19_btunnel_greyware_tool_keyword = /http\:\/\/tcp\.btunnel\.in/ nocase ascii wide
                        $string20_btunnel_greyware_tool_keyword = /https\:\/\/.{0,100}\.btunnel\.co\.in/ nocase ascii wide
                        $string21_btunnel_greyware_tool_keyword = /https\:\/\/.{0,100}\.btunnel\.co\.in/ nocase ascii wide
                        $string22_btunnel_greyware_tool_keyword = /https\:\/\/www\.btunnel\.in\/downloads/ nocase ascii wide
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