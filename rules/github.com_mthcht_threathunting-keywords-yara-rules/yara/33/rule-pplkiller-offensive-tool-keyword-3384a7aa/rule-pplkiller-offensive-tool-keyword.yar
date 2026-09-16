rule rule_PPLKiller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLKiller_offensive_tool_keyword = /\.exe\s\/disableLSAProtection/ nocase ascii wide
                        $string2_PPLKiller_offensive_tool_keyword = /\/PPLKiller\.git/ nocase ascii wide
                        $string3_PPLKiller_offensive_tool_keyword = "/PPLKiller/" nocase ascii wide
                        $string4_PPLKiller_offensive_tool_keyword = /\\PPLKiller/ nocase ascii wide
                        $string5_PPLKiller_offensive_tool_keyword = /\\Temp\\RTCore64\.sys/ nocase ascii wide
                        $string6_PPLKiller_offensive_tool_keyword = /PPLKiller\.exe/ nocase ascii wide
                        $string7_PPLKiller_offensive_tool_keyword = /PPLKiller\.sln/ nocase ascii wide
                        $string8_PPLKiller_offensive_tool_keyword = /PPLKiller\.vcxproj/ nocase ascii wide
                        $string9_PPLKiller_offensive_tool_keyword = "PPLKiller-master" nocase ascii wide
                        $string10_PPLKiller_offensive_tool_keyword = /processPIDByName.{0,1000}lsass\.exe/ nocase ascii wide

    condition:
        any of them
}