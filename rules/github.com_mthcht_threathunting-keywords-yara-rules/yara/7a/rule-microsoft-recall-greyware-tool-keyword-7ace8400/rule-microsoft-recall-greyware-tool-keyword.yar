rule rule_Microsoft_Recall_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Microsoft Recall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Microsoft Recall"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Microsoft_Recall_greyware_tool_keyword = /\\AppData\\Local\\CoreAIPlatform\.00\\UKP\\.{0,1000}\\ukg\.db/ nocase ascii wide

    condition:
        any of them
}