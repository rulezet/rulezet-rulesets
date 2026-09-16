rule dns
{
    meta:
        description = "Detection patterns for the tool 'dns' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " denied AXFR from " nocase ascii wide
                        $string2 = " dropping source port zero packet from " nocase ascii wide
                        $string3 = /\sexiting\s\(due\sto\sfatal\serror\)/ nocase ascii wide

    condition:
        any of them
}