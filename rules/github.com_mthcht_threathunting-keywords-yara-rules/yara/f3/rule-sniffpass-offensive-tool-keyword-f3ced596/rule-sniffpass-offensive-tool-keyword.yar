rule rule_SniffPass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SniffPass_offensive_tool_keyword = /\/password_sniffer\.html/ nocase ascii wide
                        $string2_SniffPass_offensive_tool_keyword = "/sniffpass-x64" nocase ascii wide
                        $string3_SniffPass_offensive_tool_keyword = /\\SniffPass\.chm/ nocase ascii wide
                        $string4_SniffPass_offensive_tool_keyword = /\\SniffPass\.pdb/ nocase ascii wide
                        $string5_SniffPass_offensive_tool_keyword = /\\sniffpass\-x64/ nocase ascii wide
                        $string6_SniffPass_offensive_tool_keyword = ">Password Sniffer<" nocase ascii wide
                        $string7_SniffPass_offensive_tool_keyword = ">SniffPass<" nocase ascii wide
                        $string8_SniffPass_offensive_tool_keyword = "1df8e073ca89d026578464b0da9748194ef62c826dea4af9848ef23b3ddf1785" nocase ascii wide
                        $string9_SniffPass_offensive_tool_keyword = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" nocase ascii wide
                        $string10_SniffPass_offensive_tool_keyword = /http\:\/\/www\.nirsoft\.net\/password_test/ nocase ascii wide
                        $string11_SniffPass_offensive_tool_keyword = "PacketSnifferClass1" nocase ascii wide
                        $string12_SniffPass_offensive_tool_keyword = /SniffPass\.exe/ nocase ascii wide
                        $string13_SniffPass_offensive_tool_keyword = /sniffpass\-x64\.zip/ nocase ascii wide
                        $string14_SniffPass_offensive_tool_keyword = /Software\\NirSoft\\SniffPass/ nocase ascii wide
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