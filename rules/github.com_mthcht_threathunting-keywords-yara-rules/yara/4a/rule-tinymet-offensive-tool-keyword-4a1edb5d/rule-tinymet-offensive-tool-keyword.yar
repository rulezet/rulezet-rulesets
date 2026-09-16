rule rule_TinyMet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TinyMet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TinyMet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TinyMet_offensive_tool_keyword = /\/tinymet\.exe/ nocase ascii wide
                        $string2_TinyMet_offensive_tool_keyword = /\\tinymet\.exe/ nocase ascii wide
                        $string3_TinyMet_offensive_tool_keyword = /0_evil\.com_4444\.exe/ nocase ascii wide
                        $string4_TinyMet_offensive_tool_keyword = "331952cdf2781133eafa25e3115db3e9cfb2cbf9b208fbcb6a462eab2e314343" nocase ascii wide
                        $string5_TinyMet_offensive_tool_keyword = "3e8b305a4b6157e6f3ed492c596cfda37d27bf63e1532516aa96ec10eed3d166" nocase ascii wide
                        $string6_TinyMet_offensive_tool_keyword = "DA06A931-7DCA-4149-853D-641B8FAA1AB9" nocase ascii wide
                        $string7_TinyMet_offensive_tool_keyword = /TinyMet\sv0\.2\\ntinymet\.com/ nocase ascii wide
                        $string8_TinyMet_offensive_tool_keyword = /www\.tinymet\.com/ nocase ascii wide

    condition:
        any of them
}