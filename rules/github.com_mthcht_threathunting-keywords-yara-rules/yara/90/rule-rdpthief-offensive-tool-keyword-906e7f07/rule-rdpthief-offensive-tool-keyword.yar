rule rule_RdpThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RdpThief_offensive_tool_keyword = "/RdpThief" nocase ascii wide
                        $string2_RdpThief_offensive_tool_keyword = /\/RdpThief\.git/ nocase ascii wide
                        $string3_RdpThief_offensive_tool_keyword = /\\RdpThief\./ nocase ascii wide
                        $string4_RdpThief_offensive_tool_keyword = /\\RdpThief_x64\./ nocase ascii wide
                        $string5_RdpThief_offensive_tool_keyword = "0x09AL/RdpThief" nocase ascii wide
                        $string6_RdpThief_offensive_tool_keyword = "71461ca71bcebb5fefa9394fe8e9a5a47c102195064d1f4cb5f24d330c9be97d" nocase ascii wide
                        $string7_RdpThief_offensive_tool_keyword = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
                        $string8_RdpThief_offensive_tool_keyword = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
                        $string9_RdpThief_offensive_tool_keyword = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
                        $string10_RdpThief_offensive_tool_keyword = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
                        $string11_RdpThief_offensive_tool_keyword = "cd7e4cd71cb803de24f7b8fc6c6946f96e9b9a95dd3c0888309b42446ba87b94" nocase ascii wide
                        $string12_RdpThief_offensive_tool_keyword = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
                        $string13_RdpThief_offensive_tool_keyword = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
                        $string14_RdpThief_offensive_tool_keyword = "Disabling RdpThief" nocase ascii wide
                        $string15_RdpThief_offensive_tool_keyword = "RdpThief enabled " nocase ascii wide
                        $string16_RdpThief_offensive_tool_keyword = /RdpThief\.dll/ nocase ascii wide
                        $string17_RdpThief_offensive_tool_keyword = /RdpThief\.exe/ nocase ascii wide
                        $string18_RdpThief_offensive_tool_keyword = /RdpThief_x64\.tmp/ nocase ascii wide
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