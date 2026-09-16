rule rule_SharpWSUS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpWSUS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWSUS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpWSUS_offensive_tool_keyword = /\.exe\screate\s\/payload.{0,1000}\s\/kb/ nocase ascii wide
                        $string2_SharpWSUS_offensive_tool_keyword = "/SharpWSUS" nocase ascii wide
                        $string3_SharpWSUS_offensive_tool_keyword = "sharpwsus locate" nocase ascii wide
                        $string4_SharpWSUS_offensive_tool_keyword = "SharpWSUS" nocase ascii wide
                        $string5_SharpWSUS_offensive_tool_keyword = /SharpWSUS\./ nocase ascii wide

    condition:
        any of them
}