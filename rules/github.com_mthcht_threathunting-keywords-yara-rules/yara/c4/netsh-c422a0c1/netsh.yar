rule netsh
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /netsh.{0,1000}\sfirewall\sset\sopmode\sdisable/ nocase ascii wide

    condition:
        any of them
}