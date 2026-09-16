rule rule_SharpSecDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSecDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSecDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSecDump_offensive_tool_keyword = /\/SharpSecDump\.git/ nocase ascii wide
                        $string2_SharpSecDump_offensive_tool_keyword = "4bb5b8961566bdbdc3787a847a55730ce32d1822677bcd7c412cf2d7f54262fd" nocase ascii wide
                        $string3_SharpSecDump_offensive_tool_keyword = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" nocase ascii wide
                        $string4_SharpSecDump_offensive_tool_keyword = "fbee25dd2d6b1faf917f4f6a90113e3c520125f325915b7dd70f304dd2dab4b1" nocase ascii wide
                        $string5_SharpSecDump_offensive_tool_keyword = "G0ldenGunSec/SharpSecDump" nocase ascii wide
                        $string6_SharpSecDump_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide
                        $string7_SharpSecDump_offensive_tool_keyword = "SharpSecDump Info" nocase ascii wide
                        $string8_SharpSecDump_offensive_tool_keyword = /SharpSecDump\.csproj/ nocase ascii wide
                        $string9_SharpSecDump_offensive_tool_keyword = /SharpSecDump\.exe/ nocase ascii wide
                        $string10_SharpSecDump_offensive_tool_keyword = /SharpSecDump\.sln/ nocase ascii wide
                        $string11_SharpSecDump_offensive_tool_keyword = "SharpSecDump-master" nocase ascii wide

    condition:
        any of them
}