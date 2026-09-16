rule rule_adget_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adget' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adget"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adget_greyware_tool_keyword = /\/ADGet\.exe/ nocase ascii wide
                        $string2_adget_greyware_tool_keyword = /\\ADGet\.exe/ nocase ascii wide

    condition:
        any of them
}