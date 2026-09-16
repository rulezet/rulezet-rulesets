rule DefenderCheck
{
    meta:
        description = "Detection patterns for the tool 'DefenderCheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefenderCheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "DefenderCheck" nocase ascii wide
                        $string2 = /DefenderCheck\.exe/ nocase ascii wide
                        $string3 = "matterpreter/DefenderCheck" nocase ascii wide

    condition:
        any of them
}