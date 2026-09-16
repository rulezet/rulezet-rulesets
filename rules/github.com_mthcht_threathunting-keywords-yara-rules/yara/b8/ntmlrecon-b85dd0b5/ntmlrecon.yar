rule NTMLRecon
{
    meta:
        description = "Detection patterns for the tool 'NTMLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTMLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ntlmrecon" nocase ascii wide
                        $string2 = "/NTLMRecon" nocase ascii wide
                        $string3 = /\/NTLMRecon\.git/ nocase ascii wide
                        $string4 = /\/ntlmrecon\/.{0,1000}\.py/ nocase ascii wide
                        $string5 = /\/ntlmutil\.py/ nocase ascii wide
                        $string6 = /\/ntlmutil\.py/ nocase ascii wide
                        $string7 = /\\ntlmutil\.py/ nocase ascii wide
                        $string8 = "ntlmrecon " nocase ascii wide
                        $string9 = /ntlmrecon\.csv/ nocase ascii wide
                        $string10 = "ntlmrecon:main" nocase ascii wide
                        $string11 = /ntlmrecon\-fromfile\.csv/ nocase ascii wide
                        $string12 = "NTLMRecon-master" nocase ascii wide
                        $string13 = /ntlmrecon\-ranges\.csv/ nocase ascii wide
                        $string14 = "puzzlepeaches/NTLMRecon" nocase ascii wide
                        $string15 = "TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw==" nocase ascii wide

    condition:
        any of them
}