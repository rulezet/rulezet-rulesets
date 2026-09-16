rule rule_Hak5_Cloud_C2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Cloud C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Cloud C2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hak5_Cloud_C2_offensive_tool_keyword = "Hak5 Cloud C" nocase ascii wide

    condition:
        any of them
}