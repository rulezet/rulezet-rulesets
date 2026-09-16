rule Earth_Lusca_Operations_Tools_
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /BadPotato\.cs/ nocase ascii wide
                        $string2 = /badpotato\.exe/ nocase ascii wide
                        $string3 = "fodhelperUACBypass" nocase ascii wide
                        $string4 = /proxyLogon\.py/ nocase ascii wide
                        $string5 = /proxyshell\.py/ nocase ascii wide
                        $string6 = /proxyshell_rce\.py/ nocase ascii wide
                        $string7 = /proxyshell\-enumerate\.py/ nocase ascii wide
                        $string8 = "proxyshell-poc" nocase ascii wide
                        $string9 = "UAC-bypass" nocase ascii wide

    condition:
        any of them
}