rule rule_SharpChromium_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpChromium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpChromium"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpChromium_offensive_tool_keyword = /\/SharpChromium\.git/ nocase ascii wide
                        $string2_SharpChromium_offensive_tool_keyword = /\\SharpChromium\\/ nocase ascii wide
                        $string3_SharpChromium_offensive_tool_keyword = "djhohnstein/SharpChromium" nocase ascii wide
                        $string4_SharpChromium_offensive_tool_keyword = "F1653F20-D47D-4F29-8C55-3C835542AF5F" nocase ascii wide
                        $string5_SharpChromium_offensive_tool_keyword = /SharpChromium\.csproj/ nocase ascii wide
                        $string6_SharpChromium_offensive_tool_keyword = /SharpChromium\.exe/ nocase ascii wide
                        $string7_SharpChromium_offensive_tool_keyword = /SharpChromium\.sln/ nocase ascii wide
                        $string8_SharpChromium_offensive_tool_keyword = "SharpChromium-master" nocase ascii wide

    condition:
        any of them
}