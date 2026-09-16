rule rule_dnschef_ng_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnschef-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnschef-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnschef_ng_offensive_tool_keyword = /\sdnschef\.exe/ nocase ascii wide
                        $string2_dnschef_ng_offensive_tool_keyword = /\sdnschef\.py/ nocase ascii wide
                        $string3_dnschef_ng_offensive_tool_keyword = /\s\-\-fakealias\swww\.fake\.com/ nocase ascii wide
                        $string4_dnschef_ng_offensive_tool_keyword = " --fakedomains " nocase ascii wide
                        $string5_dnschef_ng_offensive_tool_keyword = " --fakeip " nocase ascii wide
                        $string6_dnschef_ng_offensive_tool_keyword = " --fakeipv6 " nocase ascii wide
                        $string7_dnschef_ng_offensive_tool_keyword = " --fakemail " nocase ascii wide
                        $string8_dnschef_ng_offensive_tool_keyword = /\/dnschef\.exe/ nocase ascii wide
                        $string9_dnschef_ng_offensive_tool_keyword = /\/dnschef\.ini/
                        $string10_dnschef_ng_offensive_tool_keyword = /\/dnschef\.log/
                        $string11_dnschef_ng_offensive_tool_keyword = /\/dnschef\.py/ nocase ascii wide
                        $string12_dnschef_ng_offensive_tool_keyword = /\/dnschef\-ng\.git/ nocase ascii wide
                        $string13_dnschef_ng_offensive_tool_keyword = "/dnschef-ng/" nocase ascii wide
                        $string14_dnschef_ng_offensive_tool_keyword = /\\dnschef\.exe/ nocase ascii wide
                        $string15_dnschef_ng_offensive_tool_keyword = /\\dnschef\.ini/ nocase ascii wide
                        $string16_dnschef_ng_offensive_tool_keyword = /\\dnschef\.log/ nocase ascii wide
                        $string17_dnschef_ng_offensive_tool_keyword = /\\dnschef\.py/ nocase ascii wide
                        $string18_dnschef_ng_offensive_tool_keyword = /\\dnschef\-ng\\/ nocase ascii wide
                        $string19_dnschef_ng_offensive_tool_keyword = "byt3bl33d3r/dnschef-ng" nocase ascii wide
                        $string20_dnschef_ng_offensive_tool_keyword = /byt3bl33d3r\@pm\.me/ nocase ascii wide
                        $string21_dnschef_ng_offensive_tool_keyword = /cooking\sA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string22_dnschef_ng_offensive_tool_keyword = /cooking\sAAAA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string23_dnschef_ng_offensive_tool_keyword = "cooking all A replies to point to " nocase ascii wide
                        $string24_dnschef_ng_offensive_tool_keyword = "cooking all AAAA replies to point to " nocase ascii wide
                        $string25_dnschef_ng_offensive_tool_keyword = "cooking all CNAME replies to point to " nocase ascii wide
                        $string26_dnschef_ng_offensive_tool_keyword = "cooking all MX replies to point to " nocase ascii wide
                        $string27_dnschef_ng_offensive_tool_keyword = "cooking all NS replies to point to " nocase ascii wide
                        $string28_dnschef_ng_offensive_tool_keyword = /cooking\sCNAME\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string29_dnschef_ng_offensive_tool_keyword = /cooking\sMX\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string30_dnschef_ng_offensive_tool_keyword = /cooking\sNS\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string31_dnschef_ng_offensive_tool_keyword = /dnschef\.exe\s/ nocase ascii wide
                        $string32_dnschef_ng_offensive_tool_keyword = /dnschef\.logger/ nocase ascii wide
                        $string33_dnschef_ng_offensive_tool_keyword = /dnschef\.py\s/ nocase ascii wide
                        $string34_dnschef_ng_offensive_tool_keyword = /dnschef\.utils/ nocase ascii wide
                        $string35_dnschef_ng_offensive_tool_keyword = "dnschef-ng-main" nocase ascii wide
                        $string36_dnschef_ng_offensive_tool_keyword = /\-\-file\sdnschef\.ini\s/ nocase ascii wide
                        $string37_dnschef_ng_offensive_tool_keyword = "pip install dnschef" nocase ascii wide
                        $string38_dnschef_ng_offensive_tool_keyword = /shit\.fuck\.org/ nocase ascii wide
                        $string39_dnschef_ng_offensive_tool_keyword = /something\.wattahog\.org/ nocase ascii wide

    condition:
        any of them
}