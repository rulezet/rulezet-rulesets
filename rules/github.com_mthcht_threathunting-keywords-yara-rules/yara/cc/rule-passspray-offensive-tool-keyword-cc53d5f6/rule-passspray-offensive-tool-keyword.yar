rule rule_PassSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PassSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PassSpray_offensive_tool_keyword = /\sPassSpray\.ps1/ nocase ascii wide
                        $string2_PassSpray_offensive_tool_keyword = /\/PassSpray\.git/ nocase ascii wide
                        $string3_PassSpray_offensive_tool_keyword = /\/PassSpray\.ps1/ nocase ascii wide
                        $string4_PassSpray_offensive_tool_keyword = /\\PassSpray\.ps1/ nocase ascii wide
                        $string5_PassSpray_offensive_tool_keyword = "24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f" nocase ascii wide
                        $string6_PassSpray_offensive_tool_keyword = "Invoke-PassSpray" nocase ascii wide
                        $string7_PassSpray_offensive_tool_keyword = "Leo4j/PassSpray" nocase ascii wide

    condition:
        any of them
}