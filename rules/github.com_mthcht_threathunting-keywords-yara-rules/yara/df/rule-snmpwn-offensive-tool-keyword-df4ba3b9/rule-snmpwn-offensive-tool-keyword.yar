rule rule_snmpwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snmpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_snmpwn_offensive_tool_keyword = /\/snmpwn\.git/ nocase ascii wide
                        $string2_snmpwn_offensive_tool_keyword = /\/snmpwn\.rb/ nocase ascii wide
                        $string3_snmpwn_offensive_tool_keyword = "hatlord/snmpwn" nocase ascii wide
                        $string4_snmpwn_offensive_tool_keyword = /snmpwn\s.{0,1000}passwords\.txt/ nocase ascii wide
                        $string5_snmpwn_offensive_tool_keyword = /snmpwn\.rb.{0,1000}\s\-\-hosts\s/ nocase ascii wide

    condition:
        any of them
}