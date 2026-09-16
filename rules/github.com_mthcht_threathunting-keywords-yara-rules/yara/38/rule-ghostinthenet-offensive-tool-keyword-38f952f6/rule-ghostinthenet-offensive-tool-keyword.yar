rule rule_GhostInTheNet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GhostInTheNet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostInTheNet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GhostInTheNet_offensive_tool_keyword = /\/GhostInTheNet\.git/
                        $string2_GhostInTheNet_offensive_tool_keyword = /\/GhostInTheNet\.sh/
                        $string3_GhostInTheNet_offensive_tool_keyword = "/GhostInTheNet-master"
                        $string4_GhostInTheNet_offensive_tool_keyword = /\/tmp\/host\.ghost/
                        $string5_GhostInTheNet_offensive_tool_keyword = /\/tmp\/mac\.ghost/
                        $string6_GhostInTheNet_offensive_tool_keyword = "GhostInTheNet off"
                        $string7_GhostInTheNet_offensive_tool_keyword = "GhostInTheNet on"
                        $string8_GhostInTheNet_offensive_tool_keyword = /GhostInTheNet\.sh\s/

    condition:
        any of them
}