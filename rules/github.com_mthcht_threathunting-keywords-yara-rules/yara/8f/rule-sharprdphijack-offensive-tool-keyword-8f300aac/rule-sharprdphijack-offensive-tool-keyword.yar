rule rule_SharpRDPHijack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPHijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPHijack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpRDPHijack_offensive_tool_keyword = "- RDP Session Hijack" nocase ascii wide
                        $string2_SharpRDPHijack_offensive_tool_keyword = " SharpRDPHijack" nocase ascii wide
                        $string3_SharpRDPHijack_offensive_tool_keyword = /\.exe\s\-\-session\=2\s\-\-shadow\s\-\-console/ nocase ascii wide
                        $string4_SharpRDPHijack_offensive_tool_keyword = "/SharpRDPHijack" nocase ascii wide
                        $string5_SharpRDPHijack_offensive_tool_keyword = /\-\\nSharp\sRDP\sHijack\\n\-/ nocase ascii wide
                        $string6_SharpRDPHijack_offensive_tool_keyword = /\\SharpRDPHijack/ nocase ascii wide
                        $string7_SharpRDPHijack_offensive_tool_keyword = "622f3304b381b2f3a99567be78a668e21c1c6a405320da78a2af32addbc29d88" nocase ascii wide
                        $string8_SharpRDPHijack_offensive_tool_keyword = "Benjamin Delpy - RDP Session Tradecraft" nocase ascii wide
                        $string9_SharpRDPHijack_offensive_tool_keyword = /blog\.gentilkiwi\.com\/securite\/vol\-de\-session\-rdp/ nocase ascii wide
                        $string10_SharpRDPHijack_offensive_tool_keyword = "Hijack Remote Desktop session #4 with knowledge of the logged-on user" nocase ascii wide
                        $string11_SharpRDPHijack_offensive_tool_keyword = /https\:\/\/www\.exploit\-db\.com\/exploits\/41607/ nocase ascii wide
                        $string12_SharpRDPHijack_offensive_tool_keyword = /Impersonate\sNT\sAUTHORITY\\\\SYSTEM\sto\shijack\ssession/ nocase ascii wide
                        $string13_SharpRDPHijack_offensive_tool_keyword = /SharpRDPHijack\.cs/ nocase ascii wide
                        $string14_SharpRDPHijack_offensive_tool_keyword = /SharpRDPHijack\.exe/ nocase ascii wide
                        $string15_SharpRDPHijack_offensive_tool_keyword = "SharpRDPHijack-master" nocase ascii wide

    condition:
        any of them
}