rule rule_apaste_info_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'apaste.info' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apaste.info"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_apaste_info_greyware_tool_keyword = /https\:\/\/apaste\.info\/p\/new/ nocase ascii wide

    condition:
        any of them
}