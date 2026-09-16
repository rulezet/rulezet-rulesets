rule rule_snmpwalk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snmpwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwalk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_snmpwalk_greyware_tool_keyword = "snmpwalk  -v1 -cpublic "
                        $string2_snmpwalk_greyware_tool_keyword = /snmpwalk\s.{0,1000}\spublic\s.{0,1000}1\.3\.6\.1\./ nocase ascii wide
                        $string3_snmpwalk_greyware_tool_keyword = "snmpwalk -c public -v1 "

    condition:
        any of them
}