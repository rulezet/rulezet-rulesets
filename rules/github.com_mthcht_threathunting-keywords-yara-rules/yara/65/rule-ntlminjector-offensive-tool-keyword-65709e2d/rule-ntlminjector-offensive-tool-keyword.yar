rule rule_NTLMInjector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTLMInjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMInjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTLMInjector_offensive_tool_keyword = /\/NTLMInjector\.git/ nocase ascii wide
                        $string2_NTLMInjector_offensive_tool_keyword = /\/SetNTLM\.ps1/ nocase ascii wide
                        $string3_NTLMInjector_offensive_tool_keyword = /\\SetNTLM\.ps1/ nocase ascii wide
                        $string4_NTLMInjector_offensive_tool_keyword = "197f8806b3b467c66ad64b187f831f10ddd71695d61a42344ae617ee62e62faa" nocase ascii wide
                        $string5_NTLMInjector_offensive_tool_keyword = "ce4255704740f395be5713b049b97814ce537c440b1249850bcb62794dcc7f56" nocase ascii wide
                        $string6_NTLMInjector_offensive_tool_keyword = "namespace NTLMInjector" nocase ascii wide
                        $string7_NTLMInjector_offensive_tool_keyword = /NTLMInjector\.ps1/ nocase ascii wide
                        $string8_NTLMInjector_offensive_tool_keyword = "public class NTLMInjector" nocase ascii wide
                        $string9_NTLMInjector_offensive_tool_keyword = "vletoux/NTLMInjector" nocase ascii wide

    condition:
        any of them
}