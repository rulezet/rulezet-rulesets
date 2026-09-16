rule rule_SharpCookieMonster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpCookieMonster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCookieMonster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpCookieMonster_offensive_tool_keyword = /execute\-assembly.{0,1000}sharpcookiemonster/ nocase ascii wide
                        $string2_SharpCookieMonster_offensive_tool_keyword = "m0rv4i/SharpCookieMonster" nocase ascii wide
                        $string3_SharpCookieMonster_offensive_tool_keyword = /SharpCookieMonster.{0,1000}WebSocket4Net\.dll/ nocase ascii wide
                        $string4_SharpCookieMonster_offensive_tool_keyword = /SharpCookieMonster\.csproj/ nocase ascii wide
                        $string5_SharpCookieMonster_offensive_tool_keyword = /SharpCookieMonster\.exe/ nocase ascii wide
                        $string6_SharpCookieMonster_offensive_tool_keyword = /SharpCookieMonster\.sln/ nocase ascii wide
                        $string7_SharpCookieMonster_offensive_tool_keyword = /SharpCookieMonsterOriginal\.exe/ nocase ascii wide

    condition:
        any of them
}