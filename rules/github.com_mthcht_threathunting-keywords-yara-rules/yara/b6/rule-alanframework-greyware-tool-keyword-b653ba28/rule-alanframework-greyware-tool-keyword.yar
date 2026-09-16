rule rule_AlanFramework_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AlanFramework_greyware_tool_keyword = /http.{0,1000}\:\/\/localhost\:8081/ nocase ascii wide

    condition:
        any of them
}