rule rule_EvtMute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EvtMute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvtMute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EvtMute_offensive_tool_keyword = /\.exe.{0,1000}\s\-\-Filter\s.{0,1000}rule\sdisable\s\{\scondition\:\strue\s\}/ nocase ascii wide
                        $string2_EvtMute_offensive_tool_keyword = /\/EvtMute\.git/ nocase ascii wide
                        $string3_EvtMute_offensive_tool_keyword = "bats3c/EvtMute" nocase ascii wide
                        $string4_EvtMute_offensive_tool_keyword = /ConvertToShellcode\.py/ nocase ascii wide
                        $string5_EvtMute_offensive_tool_keyword = "DQoNCiAgICwuICAgKCAgIC4gICAgICApICAgICAgICAgICAgICAgIiAgICAgICAgICAgICwuICAgKCAgI" nocase ascii wide
                        $string6_EvtMute_offensive_tool_keyword = /EvtMuteHook\.dll/ nocase ascii wide
                        $string7_EvtMute_offensive_tool_keyword = /EvtMuteHook\.dll/ nocase ascii wide
                        $string8_EvtMute_offensive_tool_keyword = /EvtMuteHook\.iobj/ nocase ascii wide
                        $string9_EvtMute_offensive_tool_keyword = /EvtMuteHook\.ipdb/ nocase ascii wide
                        $string10_EvtMute_offensive_tool_keyword = /EvtMuteHook\.pdb/ nocase ascii wide
                        $string11_EvtMute_offensive_tool_keyword = /EvtMuteHook\.sln/ nocase ascii wide
                        $string12_EvtMute_offensive_tool_keyword = "EvtMute-master" nocase ascii wide
                        $string13_EvtMute_offensive_tool_keyword = "JG1lbnUgPSAiIgppZiAoJGZ1bmNpb25lc19wcmV2aWFzLmNvdW50IC1sZSAxKSB" nocase ascii wide
                        $string14_EvtMute_offensive_tool_keyword = "JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKcHVibGl" nocase ascii wide
                        $string15_EvtMute_offensive_tool_keyword = /SharpEvtMute\.cs/ nocase ascii wide
                        $string16_EvtMute_offensive_tool_keyword = /SharpEvtMute\.exe/ nocase ascii wide
                        $string17_EvtMute_offensive_tool_keyword = /SharpEvtMute\.pdb/ nocase ascii wide
                        $string18_EvtMute_offensive_tool_keyword = /SharpEvtMute\.sln/ nocase ascii wide
                        $string19_EvtMute_offensive_tool_keyword = /ShellcodeRDI\.py/ nocase ascii wide
                        $string20_EvtMute_offensive_tool_keyword = /YaraFilters.{0,1000}lsassdump\.yar/ nocase ascii wide
                        $string21_EvtMute_offensive_tool_keyword = "ZnVuY3Rpb24gRG9udXQtTG9hZGVyIHtwYXJhbSgkcHJvY2Vzc19pZCwkZG9udXRmaWx" nocase ascii wide
                        $string22_EvtMute_offensive_tool_keyword = "ZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y" nocase ascii wide
                        $string23_EvtMute_offensive_tool_keyword = "ZnVuY3Rpb24gSW52b2tlLUJpbmFyeSB7cGFyYW0oJGFyZykKICAgICRoZWxwPUAi" nocase ascii wide

    condition:
        any of them
}