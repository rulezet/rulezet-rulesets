rule IKEForce
{
    meta:
        description = "Detection patterns for the tool 'IKEForce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IKEForce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/IKEForce"
                        $string2 = /ikeforce\.py/

    condition:
        any of them
}