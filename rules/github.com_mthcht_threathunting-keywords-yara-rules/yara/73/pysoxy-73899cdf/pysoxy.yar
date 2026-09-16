rule pysoxy
{
    meta:
        description = "Detection patterns for the tool 'pysoxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/pysoxy\.git/ nocase ascii wide
                        $string2 = /\/pysoxy\.py/ nocase ascii wide
                        $string3 = /\\pysoxy\.py/ nocase ascii wide
                        $string4 = "MisterDaneel/pysoxy" nocase ascii wide
                        $string5 = "pysoxy-master" nocase ascii wide

    condition:
        any of them
}