rule hping
{
    meta:
        description = "Detection patterns for the tool 'hping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hping"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " hping3 " nocase ascii wide
                        $string2 = /\.\/hping\s/
                        $string3 = "antirez/hping" nocase ascii wide
                        $string4 = /hping2\.h/ nocase ascii wide
                        $string5 = "hping3 -" nocase ascii wide
                        $string6 = "install hping3" nocase ascii wide

    condition:
        any of them
}