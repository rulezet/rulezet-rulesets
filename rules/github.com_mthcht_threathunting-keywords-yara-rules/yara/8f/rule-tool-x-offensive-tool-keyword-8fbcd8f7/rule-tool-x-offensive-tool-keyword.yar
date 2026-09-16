rule rule_Tool_X_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tool-X' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tool-X"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Tool_X_offensive_tool_keyword = /\/Tool\-X\.git/
                        $string2_Tool_X_offensive_tool_keyword = "rajkumardusad/Tool-X"

    condition:
        any of them
}