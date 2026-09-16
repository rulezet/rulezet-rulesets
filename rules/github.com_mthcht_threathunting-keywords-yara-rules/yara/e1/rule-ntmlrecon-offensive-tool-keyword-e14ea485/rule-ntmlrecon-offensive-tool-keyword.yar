rule rule_NTMLRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTMLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTMLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTMLRecon_offensive_tool_keyword = " ntlmrecon" nocase ascii wide
                        $string2_NTMLRecon_offensive_tool_keyword = "/NTLMRecon" nocase ascii wide
                        $string3_NTMLRecon_offensive_tool_keyword = /\/NTLMRecon\.git/ nocase ascii wide
                        $string4_NTMLRecon_offensive_tool_keyword = /\/ntlmrecon\/.{0,1000}\.py/ nocase ascii wide
                        $string5_NTMLRecon_offensive_tool_keyword = /\/ntlmutil\.py/ nocase ascii wide
                        $string6_NTMLRecon_offensive_tool_keyword = /\/ntlmutil\.py/ nocase ascii wide
                        $string7_NTMLRecon_offensive_tool_keyword = /\\ntlmutil\.py/ nocase ascii wide
                        $string8_NTMLRecon_offensive_tool_keyword = "ntlmrecon " nocase ascii wide
                        $string9_NTMLRecon_offensive_tool_keyword = /ntlmrecon\.csv/ nocase ascii wide
                        $string10_NTMLRecon_offensive_tool_keyword = "ntlmrecon:main" nocase ascii wide
                        $string11_NTMLRecon_offensive_tool_keyword = /ntlmrecon\-fromfile\.csv/ nocase ascii wide
                        $string12_NTMLRecon_offensive_tool_keyword = "NTLMRecon-master" nocase ascii wide
                        $string13_NTMLRecon_offensive_tool_keyword = /ntlmrecon\-ranges\.csv/ nocase ascii wide
                        $string14_NTMLRecon_offensive_tool_keyword = "puzzlepeaches/NTLMRecon" nocase ascii wide
                        $string15_NTMLRecon_offensive_tool_keyword = "TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw==" nocase ascii wide

    condition:
        any of them
}