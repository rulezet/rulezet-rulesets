rule rule_SharpAltSecIds_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpAltSecIds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAltSecIds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpAltSecIds_offensive_tool_keyword = /\sadd\s\/target\:.{0,1000}\s\/altsecid\:X509\:/ nocase ascii wide
                        $string2_SharpAltSecIds_offensive_tool_keyword = /\/SharpAltSecIds\.exe/ nocase ascii wide
                        $string3_SharpAltSecIds_offensive_tool_keyword = /\/SharpAltSecIds\.git/ nocase ascii wide
                        $string4_SharpAltSecIds_offensive_tool_keyword = /\[\+\]\sAdded\s\{altsecid\}\sto\s\{target\}/ nocase ascii wide
                        $string5_SharpAltSecIds_offensive_tool_keyword = /\\SharpAltSecIds\.exe/ nocase ascii wide
                        $string6_SharpAltSecIds_offensive_tool_keyword = /\\SharpAltSecIds\.sln/ nocase ascii wide
                        $string7_SharpAltSecIds_offensive_tool_keyword = /\\SharpAltSecIds\-master/ nocase ascii wide
                        $string8_SharpAltSecIds_offensive_tool_keyword = ">SharpAltSecIds<" nocase ascii wide
                        $string9_SharpAltSecIds_offensive_tool_keyword = "5e00926cb43b56a330532ce5c4f0988172d49d28840ed490526976a7b2ea2479" nocase ascii wide
                        $string10_SharpAltSecIds_offensive_tool_keyword = "623F0079-5871-4237-B872-70FDFC2D8C52" nocase ascii wide
                        $string11_SharpAltSecIds_offensive_tool_keyword = "bugch3ck/SharpAltSecIds" nocase ascii wide
                        $string12_SharpAltSecIds_offensive_tool_keyword = "d6304a65276af87fe87a4cddf75f571d1c73c601710fffebe9da17d762d521d2" nocase ascii wide
                        $string13_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds add" nocase ascii wide
                        $string14_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds by @bugch3ck" nocase ascii wide
                        $string15_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds command" nocase ascii wide
                        $string16_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds l /target:" nocase ascii wide
                        $string17_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds list" nocase ascii wide
                        $string18_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds r /target:" nocase ascii wide
                        $string19_SharpAltSecIds_offensive_tool_keyword = "SharpAltSecIds remove" nocase ascii wide

    condition:
        any of them
}