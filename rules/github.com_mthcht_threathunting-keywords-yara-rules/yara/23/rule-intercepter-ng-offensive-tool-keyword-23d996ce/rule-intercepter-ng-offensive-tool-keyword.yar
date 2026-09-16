rule rule_Intercepter_NG_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Intercepter-NG' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Intercepter-NG"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Intercepter_NG_offensive_tool_keyword = /\/Intercepter\-NG.{0,1000}\.apk/ nocase ascii wide
                        $string2_Intercepter_NG_offensive_tool_keyword = /http\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
                        $string3_Intercepter_NG_offensive_tool_keyword = /http\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
                        $string4_Intercepter_NG_offensive_tool_keyword = /https\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
                        $string5_Intercepter_NG_offensive_tool_keyword = /https\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
                        $string6_Intercepter_NG_offensive_tool_keyword = "Intercepter-NG" nocase ascii wide
                        $string7_Intercepter_NG_offensive_tool_keyword = /Intercepter\-NG\-1\.0\.zip/ nocase ascii wide
                        $string8_Intercepter_NG_offensive_tool_keyword = /Intercepter\-NG\-1\.3\.zip/ nocase ascii wide
                        $string9_Intercepter_NG_offensive_tool_keyword = /sniff\.su\/Intercepter\-NG/ nocase ascii wide

    condition:
        any of them
}