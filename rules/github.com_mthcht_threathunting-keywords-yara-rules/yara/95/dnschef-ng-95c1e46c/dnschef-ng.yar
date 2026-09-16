rule dnschef_ng
{
    meta:
        description = "Detection patterns for the tool 'dnschef-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnschef-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdnschef\.exe/ nocase ascii wide
                        $string2 = /\sdnschef\.py/ nocase ascii wide
                        $string3 = /\s\-\-fakealias\swww\.fake\.com/ nocase ascii wide
                        $string4 = " --fakedomains " nocase ascii wide
                        $string5 = " --fakeip " nocase ascii wide
                        $string6 = " --fakeipv6 " nocase ascii wide
                        $string7 = " --fakemail " nocase ascii wide
                        $string8 = /\/dnschef\.exe/ nocase ascii wide
                        $string9 = /\/dnschef\.ini/
                        $string10 = /\/dnschef\.log/
                        $string11 = /\/dnschef\.py/ nocase ascii wide
                        $string12 = /\/dnschef\-ng\.git/ nocase ascii wide
                        $string13 = "/dnschef-ng/" nocase ascii wide
                        $string14 = /\\dnschef\.exe/ nocase ascii wide
                        $string15 = /\\dnschef\.ini/ nocase ascii wide
                        $string16 = /\\dnschef\.log/ nocase ascii wide
                        $string17 = /\\dnschef\.py/ nocase ascii wide
                        $string18 = /\\dnschef\-ng\\/ nocase ascii wide
                        $string19 = "byt3bl33d3r/dnschef-ng" nocase ascii wide
                        $string20 = /byt3bl33d3r\@pm\.me/ nocase ascii wide
                        $string21 = /cooking\sA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string22 = /cooking\sAAAA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string23 = "cooking all A replies to point to " nocase ascii wide
                        $string24 = "cooking all AAAA replies to point to " nocase ascii wide
                        $string25 = "cooking all CNAME replies to point to " nocase ascii wide
                        $string26 = "cooking all MX replies to point to " nocase ascii wide
                        $string27 = "cooking all NS replies to point to " nocase ascii wide
                        $string28 = /cooking\sCNAME\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string29 = /cooking\sMX\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string30 = /cooking\sNS\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
                        $string31 = /dnschef\.exe\s/ nocase ascii wide
                        $string32 = /dnschef\.logger/ nocase ascii wide
                        $string33 = /dnschef\.py\s/ nocase ascii wide
                        $string34 = /dnschef\.utils/ nocase ascii wide
                        $string35 = "dnschef-ng-main" nocase ascii wide
                        $string36 = /\-\-file\sdnschef\.ini\s/ nocase ascii wide
                        $string37 = "pip install dnschef" nocase ascii wide
                        $string38 = /shit\.fuck\.org/ nocase ascii wide
                        $string39 = /something\.wattahog\.org/ nocase ascii wide

    condition:
        any of them
}