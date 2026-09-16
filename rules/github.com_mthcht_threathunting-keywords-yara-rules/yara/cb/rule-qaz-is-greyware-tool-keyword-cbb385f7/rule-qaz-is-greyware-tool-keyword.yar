rule rule_qaz_is_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'qaz.is' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.is"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_qaz_is_greyware_tool_keyword = /https\:\/\/qaz\.is\// nocase ascii wide
                        $string2_qaz_is_greyware_tool_keyword = /https\:\/\/qaz\.is\/load\// nocase ascii wide
                        $string3_qaz_is_greyware_tool_keyword = /https\:\/\/qaz\.is\/zaq\// nocase ascii wide

    condition:
        any of them
}