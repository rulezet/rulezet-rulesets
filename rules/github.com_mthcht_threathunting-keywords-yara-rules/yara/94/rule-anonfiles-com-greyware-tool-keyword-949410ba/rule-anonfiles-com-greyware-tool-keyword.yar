rule rule_anonfiles_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'anonfiles.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anonfiles.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_anonfiles_com_greyware_tool_keyword = /https\:\/\/anonfiles\.com\/.{0,1000}\// nocase ascii wide
                        $string2_anonfiles_com_greyware_tool_keyword = /https\:\/\/api\.anonfiles\.com\/upload/ nocase ascii wide

    condition:
        any of them
}