rule rule_lyncsmash_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_lyncsmash_greyware_tool_keyword = /UCCAPI\/16\.0\.13328\.20130\sOC\/16\.0\.13426\.20234/ nocase ascii wide

    condition:
        any of them
}