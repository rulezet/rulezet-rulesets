rule rule_termbin_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'termbin.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "termbin.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_termbin_com_greyware_tool_keyword = /\snc\stermbin\.com\s/ nocase ascii wide
                        $string2_termbin_com_greyware_tool_keyword = /\snetcat\stermbin\.com\s/ nocase ascii wide
                        $string3_termbin_com_greyware_tool_keyword = /\stermbin\.com\s9999/ nocase ascii wide
                        $string4_termbin_com_greyware_tool_keyword = /curl\shttps\:\/\/termbin\.com\// nocase ascii wide
                        $string5_termbin_com_greyware_tool_keyword = /https\:\/\/termbin\.com\/test/ nocase ascii wide

    condition:
        any of them
}