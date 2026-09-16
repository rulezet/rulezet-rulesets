rule rule_SimplyEmail_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SimplyEmail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimplyEmail"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SimplyEmail_offensive_tool_keyword = /\/SimplyEmail\.git/ nocase ascii wide
                        $string2_SimplyEmail_offensive_tool_keyword = /SimplyEmail\.py/ nocase ascii wide
                        $string3_SimplyEmail_offensive_tool_keyword = "SimplyEmail-master" nocase ascii wide
                        $string4_SimplyEmail_offensive_tool_keyword = "SimplySecurity/SimplyEmail" nocase ascii wide

    condition:
        any of them
}