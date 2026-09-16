rule Invoke_Pre2kSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Pre2kSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Pre2kSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Any passwords that were successfully sprayed have been output to" nocase ascii wide
                        $string2 = /\sPre2kSpray\.ps1/ nocase ascii wide
                        $string3 = " Starting pre2k spray against " nocase ascii wide
                        $string4 = /\/Pre2kSpray\.ps1/ nocase ascii wide
                        $string5 = /\\Pre2kSpray\.ps1/ nocase ascii wide
                        $string6 = "Invoke-Pre2kSpray" nocase ascii wide
                        $string7 = "Invoke-SpraySinglePassword" nocase ascii wide

    condition:
        any of them
}