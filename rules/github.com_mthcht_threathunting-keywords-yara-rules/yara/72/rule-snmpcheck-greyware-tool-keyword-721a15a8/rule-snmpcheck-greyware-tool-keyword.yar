rule rule_snmpcheck_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snmpcheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpcheck"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_snmpcheck_greyware_tool_keyword = "install snmpcheck" nocase ascii wide
                        $string2_snmpcheck_greyware_tool_keyword = /snmp\-check\s.{0,1000}\s\-c\spublic/ nocase ascii wide

    condition:
        any of them
}