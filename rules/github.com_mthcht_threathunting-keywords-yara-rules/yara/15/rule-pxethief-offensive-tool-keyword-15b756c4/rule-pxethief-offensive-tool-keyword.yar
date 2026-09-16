rule rule_pxethief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pxethief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pxethief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pxethief_offensive_tool_keyword = "/PXEThief" nocase ascii wide
                        $string2_pxethief_offensive_tool_keyword = "auto_exploit_blank_password" nocase ascii wide
                        $string3_pxethief_offensive_tool_keyword = /media_variable_file_cryptography\.py/ nocase ascii wide
                        $string4_pxethief_offensive_tool_keyword = "pxethief " nocase ascii wide
                        $string5_pxethief_offensive_tool_keyword = /pxethief\.py/ nocase ascii wide

    condition:
        any of them
}