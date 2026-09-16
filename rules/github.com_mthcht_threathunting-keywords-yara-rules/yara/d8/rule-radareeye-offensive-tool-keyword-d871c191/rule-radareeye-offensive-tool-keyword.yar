rule rule_RadareEye_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RadareEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RadareEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RadareEye_offensive_tool_keyword = /\sradare\s.{0,1000}\:.{0,1000}\s\-ble/ nocase ascii wide
                        $string2_RadareEye_offensive_tool_keyword = "souravbaghz/RadareEye" nocase ascii wide
                        $string3_RadareEye_offensive_tool_keyword = /\.\/radare\s/

    condition:
        any of them
}