rule Tool_X
{
    meta:
        description = "Detection patterns for the tool 'Tool-X' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tool-X"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Tool\-X\.git/
                        $string2 = "rajkumardusad/Tool-X"

    condition:
        any of them
}