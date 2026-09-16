rule rule_AutoSUID_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoSUID_offensive_tool_keyword = /\sAutoSUID\.sh/ nocase ascii wide
                        $string2_AutoSUID_offensive_tool_keyword = /\spwn_php\.me/ nocase ascii wide
                        $string3_AutoSUID_offensive_tool_keyword = /\spwn_python\.me/ nocase ascii wide
                        $string4_AutoSUID_offensive_tool_keyword = /\.\/AutoSUID\.sh/
                        $string5_AutoSUID_offensive_tool_keyword = /\/AutoSUID\.git/ nocase ascii wide
                        $string6_AutoSUID_offensive_tool_keyword = /\/pwn_php\.me/
                        $string7_AutoSUID_offensive_tool_keyword = /\/pwn_python\.me/
                        $string8_AutoSUID_offensive_tool_keyword = /AutoSUID\-main\./ nocase ascii wide
                        $string9_AutoSUID_offensive_tool_keyword = "aW1wb3J0IG9zOyBvcy5leGVjbCgiL2Jpbi9zaCIsICJzaCIsICItcCIp" nocase ascii wide
                        $string10_AutoSUID_offensive_tool_keyword = "IvanGlinkin/AutoSUID" nocase ascii wide
                        $string11_AutoSUID_offensive_tool_keyword = "PD9waHAKcGNudGxfZXhlYygnL2Jpbi9zaCcsIFsnLXAnXSk7Cj8" nocase ascii wide

    condition:
        any of them
}