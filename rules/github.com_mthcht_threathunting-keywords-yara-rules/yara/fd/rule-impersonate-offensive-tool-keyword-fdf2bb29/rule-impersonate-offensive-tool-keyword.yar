rule rule_impersonate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'impersonate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_impersonate_offensive_tool_keyword = /\sImpersonate\.exe\s/ nocase ascii wide
                        $string2_impersonate_offensive_tool_keyword = /\simpersonate\.py\s/ nocase ascii wide
                        $string3_impersonate_offensive_tool_keyword = /\/Impersonate\.exe/ nocase ascii wide
                        $string4_impersonate_offensive_tool_keyword = /\/impersonate\.git/ nocase ascii wide
                        $string5_impersonate_offensive_tool_keyword = /\/impersonate\.py/ nocase ascii wide
                        $string6_impersonate_offensive_tool_keyword = /\\Impersonate\.exe/ nocase ascii wide
                        $string7_impersonate_offensive_tool_keyword = /\\impersonate\.py/ nocase ascii wide
                        $string8_impersonate_offensive_tool_keyword = /\\Impersonate\\Impersonate\.cpp/ nocase ascii wide
                        $string9_impersonate_offensive_tool_keyword = /\\Temp\\Impersonate\.exe/ nocase ascii wide
                        $string10_impersonate_offensive_tool_keyword = "00630066-0B43-474E-A93B-417CF1A65195" nocase ascii wide
                        $string11_impersonate_offensive_tool_keyword = /Impersonate\.exe\sadduser\s/ nocase ascii wide
                        $string12_impersonate_offensive_tool_keyword = /Impersonate\.exe\sexec\s/ nocase ascii wide
                        $string13_impersonate_offensive_tool_keyword = /Impersonate\.exe\slist\s/ nocase ascii wide
                        $string14_impersonate_offensive_tool_keyword = /Impersonate\.exe\slist/ nocase ascii wide
                        $string15_impersonate_offensive_tool_keyword = /impersonate\-main\.zip/ nocase ascii wide
                        $string16_impersonate_offensive_tool_keyword = "sensepost/impersonate" nocase ascii wide

    condition:
        any of them
}