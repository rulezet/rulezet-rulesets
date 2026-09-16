rule snmpwalk
{
    meta:
        description = "Detection patterns for the tool 'snmpwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwalk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "snmpwalk  -v1 -cpublic "
                        $string2 = /snmpwalk\s.{0,1000}\spublic\s.{0,1000}1\.3\.6\.1\./ nocase ascii wide
                        $string3 = "snmpwalk -c public -v1 "

    condition:
        any of them
}