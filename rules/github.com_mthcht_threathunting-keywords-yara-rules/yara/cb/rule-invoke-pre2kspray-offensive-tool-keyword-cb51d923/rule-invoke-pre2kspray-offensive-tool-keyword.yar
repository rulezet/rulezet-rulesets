rule rule_Invoke_Pre2kSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Pre2kSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Pre2kSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_Pre2kSpray_offensive_tool_keyword = " Any passwords that were successfully sprayed have been output to" nocase ascii wide
                        $string2_Invoke_Pre2kSpray_offensive_tool_keyword = /\sPre2kSpray\.ps1/ nocase ascii wide
                        $string3_Invoke_Pre2kSpray_offensive_tool_keyword = " Starting pre2k spray against " nocase ascii wide
                        $string4_Invoke_Pre2kSpray_offensive_tool_keyword = /\/Pre2kSpray\.ps1/ nocase ascii wide
                        $string5_Invoke_Pre2kSpray_offensive_tool_keyword = /\\Pre2kSpray\.ps1/ nocase ascii wide
                        $string6_Invoke_Pre2kSpray_offensive_tool_keyword = "Invoke-Pre2kSpray" nocase ascii wide
                        $string7_Invoke_Pre2kSpray_offensive_tool_keyword = "Invoke-SpraySinglePassword" nocase ascii wide

    condition:
        any of them
}