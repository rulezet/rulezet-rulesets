rule rule_Earth_Lusca_Operations_Tools__offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /BadPotato\.cs/ nocase ascii wide
                        $string2_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /badpotato\.exe/ nocase ascii wide
                        $string3_Earth_Lusca_Operations_Tools__offensive_tool_keyword = "fodhelperUACBypass" nocase ascii wide
                        $string4_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /proxyLogon\.py/ nocase ascii wide
                        $string5_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /proxyshell\.py/ nocase ascii wide
                        $string6_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /proxyshell_rce\.py/ nocase ascii wide
                        $string7_Earth_Lusca_Operations_Tools__offensive_tool_keyword = /proxyshell\-enumerate\.py/ nocase ascii wide
                        $string8_Earth_Lusca_Operations_Tools__offensive_tool_keyword = "proxyshell-poc" nocase ascii wide
                        $string9_Earth_Lusca_Operations_Tools__offensive_tool_keyword = "UAC-bypass" nocase ascii wide

    condition:
        any of them
}