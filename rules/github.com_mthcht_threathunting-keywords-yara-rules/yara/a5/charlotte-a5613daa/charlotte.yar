rule charlotte
{
    meta:
        description = "Detection patterns for the tool 'charlotte' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "charlotte"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scharlotte\.cpp/ nocase ascii wide
                        $string2 = /\scharlotte\.dll\s/ nocase ascii wide
                        $string3 = /\/charlotte\.cpp/ nocase ascii wide
                        $string4 = /\/charlotte\.py/ nocase ascii wide
                        $string5 = /\\charlotte\.cpp/ nocase ascii wide
                        $string6 = /\\charlotte\.py/ nocase ascii wide
                        $string7 = "9emin1/charlotte" nocase ascii wide
                        $string8 = /charlotte\-main\.zip/ nocase ascii wide
                        $string9 = /http.{0,1000}\/charlotte\.dll/ nocase ascii wide
                        $string10 = /python.{0,1000}charlotte\.py/ nocase ascii wide
                        $string11 = /rundll32\scharlotte\.dll/ nocase ascii wide
                        $string12 = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide

    condition:
        any of them
}