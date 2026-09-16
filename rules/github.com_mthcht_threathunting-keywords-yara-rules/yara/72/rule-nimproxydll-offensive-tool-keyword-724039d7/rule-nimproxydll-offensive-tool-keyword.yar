rule rule_nimproxydll_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nimproxydll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimproxydll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nimproxydll_offensive_tool_keyword = /\screateproxydll\.sh/ nocase ascii wide
                        $string2_nimproxydll_offensive_tool_keyword = /\/createproxydll\.sh/ nocase ascii wide
                        $string3_nimproxydll_offensive_tool_keyword = /\/nimproxydll\.git/ nocase ascii wide
                        $string4_nimproxydll_offensive_tool_keyword = "/nimproxydll/" nocase ascii wide
                        $string5_nimproxydll_offensive_tool_keyword = /\\nimproxydll\\/ nocase ascii wide
                        $string6_nimproxydll_offensive_tool_keyword = /\\nimproxydll\-main\\/ nocase ascii wide
                        $string7_nimproxydll_offensive_tool_keyword = "17257046150e6cbdc59be7873210cc6e0399ba51a5da24114f3c147bdc4fdb4c" nocase ascii wide
                        $string8_nimproxydll_offensive_tool_keyword = "ab1b755120b2d5fb3db73f363a0b44881bc8b5e9699e27b804c9806b78de3a1b" nocase ascii wide
                        $string9_nimproxydll_offensive_tool_keyword = /app\/dllproxy\.nim/ nocase ascii wide
                        $string10_nimproxydll_offensive_tool_keyword = "cyllective/nimproxydll" nocase ascii wide
                        $string11_nimproxydll_offensive_tool_keyword = "make image && make proxydll" nocase ascii wide

    condition:
        any of them
}