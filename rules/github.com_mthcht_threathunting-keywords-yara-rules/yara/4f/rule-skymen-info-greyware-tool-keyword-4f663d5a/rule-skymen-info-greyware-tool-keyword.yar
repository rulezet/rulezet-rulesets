rule rule_skymen_info_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'skymen.info' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "skymen.info"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_skymen_info_greyware_tool_keyword = /https\:\/\/www\.skymem\.info\/srch\?q\=/ nocase ascii wide

    condition:
        any of them
}