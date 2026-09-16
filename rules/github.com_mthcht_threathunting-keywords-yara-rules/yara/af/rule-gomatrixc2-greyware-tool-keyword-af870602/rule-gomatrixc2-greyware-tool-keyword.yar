rule rule_goMatrixC2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_goMatrixC2_greyware_tool_keyword = /https\:\/\/matrix\.org\/_matrix\/client\/r0\/rooms\/.{0,1000}\/send\/m\.room\.message/ nocase ascii wide

    condition:
        any of them
}