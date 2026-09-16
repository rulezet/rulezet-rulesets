rule rule_themebleed_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'themebleed' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "themebleed"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_themebleed_offensive_tool_keyword = /\/ThemeBleed\.exe/ nocase ascii wide
                        $string2_themebleed_offensive_tool_keyword = /\\ThemeBleed\.exe\s/ nocase ascii wide
                        $string3_themebleed_offensive_tool_keyword = /\\ThemeBleed\.sln/ nocase ascii wide
                        $string4_themebleed_offensive_tool_keyword = "1BACEDDC-CD87-41DC-948C-1C12F960BECB" nocase ascii wide
                        $string5_themebleed_offensive_tool_keyword = /ThemeBleed\.exe\s\s/ nocase ascii wide

    condition:
        any of them
}