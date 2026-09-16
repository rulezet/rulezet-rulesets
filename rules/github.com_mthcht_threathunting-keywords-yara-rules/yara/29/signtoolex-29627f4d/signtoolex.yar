rule SignToolEx
{
    meta:
        description = "Detection patterns for the tool 'SignToolEx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SignToolEx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SignToolEx\.cpp/ nocase ascii wide
                        $string2 = /\/SignToolEx\.git/ nocase ascii wide
                        $string3 = /\/SignToolEx\.sln/ nocase ascii wide
                        $string4 = /\\SignToolEx\.cpp/ nocase ascii wide
                        $string5 = /\\SignToolEx\.sln/ nocase ascii wide
                        $string6 = /\\SignToolExDll/ nocase ascii wide
                        $string7 = "82B0EE92-347E-412F-8EA2-CBDE683EDA57" nocase ascii wide
                        $string8 = "B8AEE3F1-0642-443C-B42C-33BADCD42365" nocase ascii wide
                        $string9 = "hackerhouse-opensource/SignToolEx" nocase ascii wide
                        $string10 = /SignToolEx\.exe/ nocase ascii wide
                        $string11 = /SignToolExHook\.dll/ nocase ascii wide
                        $string12 = "SignToolEx-main" nocase ascii wide

    condition:
        any of them
}