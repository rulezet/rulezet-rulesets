rule omg_payloads
{
    meta:
        description = "Detection patterns for the tool 'omg-payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "omg-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/omg\-payloads\.git/ nocase ascii wide
                        $string2 = "hak5/omg-payloads" nocase ascii wide
                        $string3 = /omg\-payloads.{0,1000}\/payloads\// nocase ascii wide
                        $string4 = "omg-payloads-master" nocase ascii wide

    condition:
        any of them
}