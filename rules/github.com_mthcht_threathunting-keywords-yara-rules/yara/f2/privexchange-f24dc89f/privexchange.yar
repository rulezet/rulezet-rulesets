rule privexchange
{
    meta:
        description = "Detection patterns for the tool 'privexchange' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "privexchange"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PrivExchange\.git/ nocase ascii wide
                        $string2 = "dirkjanm/PrivExchange" nocase ascii wide
                        $string3 = /httpattack\.py/ nocase ascii wide
                        $string4 = /privexchange\.py/ nocase ascii wide
                        $string5 = /PrivExchange\-master\.zip/ nocase ascii wide

    condition:
        any of them
}