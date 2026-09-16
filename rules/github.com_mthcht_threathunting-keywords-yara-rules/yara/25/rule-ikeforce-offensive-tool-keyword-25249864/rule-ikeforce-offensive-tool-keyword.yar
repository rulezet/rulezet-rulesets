rule rule_IKEForce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IKEForce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IKEForce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IKEForce_offensive_tool_keyword = "/IKEForce"
                        $string2_IKEForce_offensive_tool_keyword = /ikeforce\.py/

    condition:
        any of them
}