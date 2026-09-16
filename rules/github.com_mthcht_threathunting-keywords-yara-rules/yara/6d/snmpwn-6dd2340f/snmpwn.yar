rule snmpwn
{
    meta:
        description = "Detection patterns for the tool 'snmpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/snmpwn\.git/ nocase ascii wide
                        $string2 = /\/snmpwn\.rb/ nocase ascii wide
                        $string3 = "hatlord/snmpwn" nocase ascii wide
                        $string4 = /snmpwn\s.{0,1000}passwords\.txt/ nocase ascii wide
                        $string5 = /snmpwn\.rb.{0,1000}\s\-\-hosts\s/ nocase ascii wide

    condition:
        any of them
}