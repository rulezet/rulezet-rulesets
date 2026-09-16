rule rule_charlotte_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'charlotte' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "charlotte"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_charlotte_offensive_tool_keyword = /\scharlotte\.cpp/ nocase ascii wide
                        $string2_charlotte_offensive_tool_keyword = /\scharlotte\.dll\s/ nocase ascii wide
                        $string3_charlotte_offensive_tool_keyword = /\/charlotte\.cpp/ nocase ascii wide
                        $string4_charlotte_offensive_tool_keyword = /\/charlotte\.py/ nocase ascii wide
                        $string5_charlotte_offensive_tool_keyword = /\\charlotte\.cpp/ nocase ascii wide
                        $string6_charlotte_offensive_tool_keyword = /\\charlotte\.py/ nocase ascii wide
                        $string7_charlotte_offensive_tool_keyword = "9emin1/charlotte" nocase ascii wide
                        $string8_charlotte_offensive_tool_keyword = /charlotte\-main\.zip/ nocase ascii wide
                        $string9_charlotte_offensive_tool_keyword = /http.{0,1000}\/charlotte\.dll/ nocase ascii wide
                        $string10_charlotte_offensive_tool_keyword = /python.{0,1000}charlotte\.py/ nocase ascii wide
                        $string11_charlotte_offensive_tool_keyword = /rundll32\scharlotte\.dll/ nocase ascii wide
                        $string12_charlotte_offensive_tool_keyword = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide

    condition:
        any of them
}