rule rule_SignToolEx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SignToolEx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SignToolEx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SignToolEx_offensive_tool_keyword = /\/SignToolEx\.cpp/ nocase ascii wide
                        $string2_SignToolEx_offensive_tool_keyword = /\/SignToolEx\.git/ nocase ascii wide
                        $string3_SignToolEx_offensive_tool_keyword = /\/SignToolEx\.sln/ nocase ascii wide
                        $string4_SignToolEx_offensive_tool_keyword = /\\SignToolEx\.cpp/ nocase ascii wide
                        $string5_SignToolEx_offensive_tool_keyword = /\\SignToolEx\.sln/ nocase ascii wide
                        $string6_SignToolEx_offensive_tool_keyword = /\\SignToolExDll/ nocase ascii wide
                        $string7_SignToolEx_offensive_tool_keyword = "82B0EE92-347E-412F-8EA2-CBDE683EDA57" nocase ascii wide
                        $string8_SignToolEx_offensive_tool_keyword = "B8AEE3F1-0642-443C-B42C-33BADCD42365" nocase ascii wide
                        $string9_SignToolEx_offensive_tool_keyword = "hackerhouse-opensource/SignToolEx" nocase ascii wide
                        $string10_SignToolEx_offensive_tool_keyword = /SignToolEx\.exe/ nocase ascii wide
                        $string11_SignToolEx_offensive_tool_keyword = /SignToolExHook\.dll/ nocase ascii wide
                        $string12_SignToolEx_offensive_tool_keyword = "SignToolEx-main" nocase ascii wide

    condition:
        any of them
}