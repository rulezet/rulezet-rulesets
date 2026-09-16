rule NTLMInjector
{
    meta:
        description = "Detection patterns for the tool 'NTLMInjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMInjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NTLMInjector\.git/ nocase ascii wide
                        $string2 = /\/SetNTLM\.ps1/ nocase ascii wide
                        $string3 = /\\SetNTLM\.ps1/ nocase ascii wide
                        $string4 = "197f8806b3b467c66ad64b187f831f10ddd71695d61a42344ae617ee62e62faa" nocase ascii wide
                        $string5 = "ce4255704740f395be5713b049b97814ce537c440b1249850bcb62794dcc7f56" nocase ascii wide
                        $string6 = "namespace NTLMInjector" nocase ascii wide
                        $string7 = /NTLMInjector\.ps1/ nocase ascii wide
                        $string8 = "public class NTLMInjector" nocase ascii wide
                        $string9 = "vletoux/NTLMInjector" nocase ascii wide

    condition:
        any of them
}