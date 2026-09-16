rule rule_Backstab_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Backstab' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Backstab"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Backstab_offensive_tool_keyword = /\/Backstab\.git/ nocase ascii wide
                        $string2_Backstab_offensive_tool_keyword = "/Backstab/Backstab" nocase ascii wide
                        $string3_Backstab_offensive_tool_keyword = /\/Backstab64\.exe/ nocase ascii wide
                        $string4_Backstab_offensive_tool_keyword = /\/resources\/PROCEXP\.sys/ nocase ascii wide
                        $string5_Backstab_offensive_tool_keyword = /\\Backstab\.sln/ nocase ascii wide
                        $string6_Backstab_offensive_tool_keyword = /\\Backstab64\.exe/ nocase ascii wide
                        $string7_Backstab_offensive_tool_keyword = /\\resources\\PROCEXP\.sys/ nocase ascii wide
                        $string8_Backstab_offensive_tool_keyword = "268cd1727a2d84acc991768b9d4d30adcef18dca75f357e56aa0bdc91f345fd7" nocase ascii wide
                        $string9_Backstab_offensive_tool_keyword = "307eb30c7d3640ca11f564b1dbbb7a133236c3c9b45192ddcb317477a9f54b59" nocase ascii wide
                        $string10_Backstab_offensive_tool_keyword = "9678bdc0acce5aac06e4154631a01a94bfa9c2455efb5e72c3d8cdbf2663b019" nocase ascii wide
                        $string11_Backstab_offensive_tool_keyword = "A0E7B538-F719-47B8-8BE4-A82C933F5753" nocase ascii wide
                        $string12_Backstab_offensive_tool_keyword = /backstab\.exe/ nocase ascii wide
                        $string13_Backstab_offensive_tool_keyword = /Backstab\.sln/ nocase ascii wide
                        $string14_Backstab_offensive_tool_keyword = "Backstab/Driverloading" nocase ascii wide
                        $string15_Backstab_offensive_tool_keyword = "Backstab-master" nocase ascii wide
                        $string16_Backstab_offensive_tool_keyword = "bff5c33032fc4d1a25a3a569e72910b2dc500caf44b0d0baac16c4abd3868998" nocase ascii wide
                        $string17_Backstab_offensive_tool_keyword = "Yaxser/Backstab" nocase ascii wide

    condition:
        any of them
}