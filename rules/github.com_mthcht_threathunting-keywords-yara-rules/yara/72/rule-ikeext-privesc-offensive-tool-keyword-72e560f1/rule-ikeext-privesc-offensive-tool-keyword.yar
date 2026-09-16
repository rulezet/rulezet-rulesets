rule rule_Ikeext_Privesc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ikeext-Privesc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ikeext-Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ikeext_Privesc_offensive_tool_keyword = /\/Ikeext\-Privesc\.git/ nocase ascii wide
                        $string2_Ikeext_Privesc_offensive_tool_keyword = /\\Ikeext\-Privesc/ nocase ascii wide
                        $string3_Ikeext_Privesc_offensive_tool_keyword = "57c1670e15a47e02637545cc4a3ad421000a98279df961fc6d454a5c0271421e" nocase ascii wide
                        $string4_Ikeext_Privesc_offensive_tool_keyword = /DllInjection\.dll/ nocase ascii wide
                        $string5_Ikeext_Privesc_offensive_tool_keyword = "IKEEXT DLL Hijacking" nocase ascii wide
                        $string6_Ikeext_Privesc_offensive_tool_keyword = /Ikeext\-Privesc\.ps1/ nocase ascii wide
                        $string7_Ikeext_Privesc_offensive_tool_keyword = "Invoke-IkeextCheck" nocase ascii wide
                        $string8_Ikeext_Privesc_offensive_tool_keyword = "Invoke-IkeextExploit" nocase ascii wide
                        $string9_Ikeext_Privesc_offensive_tool_keyword = "net stop IKEEXT" nocase ascii wide
                        $string10_Ikeext_Privesc_offensive_tool_keyword = "securycore/Ikeext-Privesc" nocase ascii wide
                        $string11_Ikeext_Privesc_offensive_tool_keyword = /The\sexploit\sis\sready\.\sA\sreboot\sis\snow\srequired\sto\strigger\sit/ nocase ascii wide
                        $string12_Ikeext_Privesc_offensive_tool_keyword = /TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAADn8UE/ nocase ascii wide
                        $string13_Ikeext_Privesc_offensive_tool_keyword = "W0lLRUVYVF0NCk1FRElBPXJhc3RhcGkNClBvcnQ9VlBOMi0wDQpEZXZpY2U9V2FuIE1pbmlwb3J0IChJS0V2MikNCkRFVklDRT12cG4NClBob25lTnVtYmVyPTEyNy4wLjAuMQ==" nocase ascii wide
                        $string14_Ikeext_Privesc_offensive_tool_keyword = /wlbsctrl_payload\.bat/ nocase ascii wide

    condition:
        any of them
}