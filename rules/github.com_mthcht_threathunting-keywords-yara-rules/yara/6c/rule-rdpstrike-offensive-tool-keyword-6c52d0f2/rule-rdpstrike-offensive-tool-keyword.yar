rule rule_RdpStrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RdpStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RdpStrike_offensive_tool_keyword = /\\"RdpStrike\.cna\\"/ nocase ascii wide
                        $string2_RdpStrike_offensive_tool_keyword = /\/RdpStrike\.git/ nocase ascii wide
                        $string3_RdpStrike_offensive_tool_keyword = /\\RdpStrike\.asm/ nocase ascii wide
                        $string4_RdpStrike_offensive_tool_keyword = /\\RdpStrike\.cna/ nocase ascii wide
                        $string5_RdpStrike_offensive_tool_keyword = /\\RdpStrike\\/ nocase ascii wide
                        $string6_RdpStrike_offensive_tool_keyword = "0xEr3bus/RdpStrike" nocase ascii wide
                        $string7_RdpStrike_offensive_tool_keyword = "227cc3d2c07ef203c39afe00c81943cf245d626c1efa1b32024d7229604635e5" nocase ascii wide
                        $string8_RdpStrike_offensive_tool_keyword = "Disabling RDPStrike" nocase ascii wide
                        $string9_RdpStrike_offensive_tool_keyword = /Injecting\sinto\smstsc\.exe/ nocase ascii wide
                        $string10_RdpStrike_offensive_tool_keyword = "RDPStrike enabled" nocase ascii wide
                        $string11_RdpStrike_offensive_tool_keyword = /RdpStrike\.x64\.bin/ nocase ascii wide

    condition:
        any of them
}