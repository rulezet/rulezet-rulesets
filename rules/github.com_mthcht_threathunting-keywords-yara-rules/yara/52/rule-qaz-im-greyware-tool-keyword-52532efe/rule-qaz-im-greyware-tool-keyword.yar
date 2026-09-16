rule rule_qaz_im_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'qaz.im' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.im"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_qaz_im_greyware_tool_keyword = /https\:\/\/qaz\.im\// nocase ascii wide
                        $string2_qaz_im_greyware_tool_keyword = /https\:\/\/qaz\.im\/load\// nocase ascii wide
                        $string3_qaz_im_greyware_tool_keyword = /https\:\/\/qaz\.im\/zaq\// nocase ascii wide

    condition:
        any of them
}