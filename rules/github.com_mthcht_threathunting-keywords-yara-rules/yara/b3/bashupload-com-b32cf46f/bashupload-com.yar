rule bashupload_com
{
    meta:
        description = "Detection patterns for the tool 'bashupload.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bashupload.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/bashupload\.com/ nocase ascii wide

    condition:
        any of them
}