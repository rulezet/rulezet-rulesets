rule rule_Harvester_OF_SORROW_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Harvester_OF_SORROW' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Harvester_OF_SORROW"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Harvester_OF_SORROW_offensive_tool_keyword = /\sPictures\\Screenshots\\loot\.zip/ nocase ascii wide
                        $string2_Harvester_OF_SORROW_offensive_tool_keyword = "REM Title: Harvester_OF_SORROW" nocase ascii wide
                        $string3_Harvester_OF_SORROW_offensive_tool_keyword = "STRING firefox about:logins" nocase ascii wide

    condition:
        any of them
}