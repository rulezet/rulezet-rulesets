rule rule_produkey_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'produkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "produkey"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_produkey_greyware_tool_keyword = /\/ProduKey\.exe/ nocase ascii wide
                        $string2_produkey_greyware_tool_keyword = /\\ProduKey\.exe/ nocase ascii wide
                        $string3_produkey_greyware_tool_keyword = /produkey\.zip/ nocase ascii wide
                        $string4_produkey_greyware_tool_keyword = /produkey_setup\.exe/ nocase ascii wide
                        $string5_produkey_greyware_tool_keyword = /produkey\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}