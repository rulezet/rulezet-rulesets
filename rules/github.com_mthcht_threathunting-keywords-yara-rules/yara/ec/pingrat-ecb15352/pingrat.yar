rule PingRAT
{
    meta:
        description = "Detection patterns for the tool 'PingRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PingRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PingRAT\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sICMP\slistener\sstarted\!/ nocase ascii wide
                        $string3 = /\\PingRAT\\/ nocase ascii wide
                        $string4 = /PingRAT\.exe/ nocase ascii wide
                        $string5 = "umutcamliyurt/PingRAT" nocase ascii wide

    condition:
        any of them
}