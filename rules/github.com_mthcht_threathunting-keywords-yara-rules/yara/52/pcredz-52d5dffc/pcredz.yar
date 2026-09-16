rule Pcredz
{
    meta:
        description = "Detection patterns for the tool 'Pcredz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pcredz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/Pcredz\s/
                        $string2 = "lgandx/Pcredz" nocase ascii wide
                        $string3 = "Pcredz -d " nocase ascii wide
                        $string4 = "Pcredz -f " nocase ascii wide
                        $string5 = "Pcredz -i " nocase ascii wide

    condition:
        any of them
}