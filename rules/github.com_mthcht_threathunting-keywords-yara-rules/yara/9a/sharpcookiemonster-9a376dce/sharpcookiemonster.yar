rule SharpCookieMonster
{
    meta:
        description = "Detection patterns for the tool 'SharpCookieMonster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCookieMonster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /execute\-assembly.{0,1000}sharpcookiemonster/ nocase ascii wide
                        $string2 = "m0rv4i/SharpCookieMonster" nocase ascii wide
                        $string3 = /SharpCookieMonster.{0,1000}WebSocket4Net\.dll/ nocase ascii wide
                        $string4 = /SharpCookieMonster\.csproj/ nocase ascii wide
                        $string5 = /SharpCookieMonster\.exe/ nocase ascii wide
                        $string6 = /SharpCookieMonster\.sln/ nocase ascii wide
                        $string7 = /SharpCookieMonsterOriginal\.exe/ nocase ascii wide

    condition:
        any of them
}