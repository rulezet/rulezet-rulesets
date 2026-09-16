rule RdpStrike
{
    meta:
        description = "Detection patterns for the tool 'RdpStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\"RdpStrike\.cna\\"/ nocase ascii wide
                        $string2 = /\/RdpStrike\.git/ nocase ascii wide
                        $string3 = /\\RdpStrike\.asm/ nocase ascii wide
                        $string4 = /\\RdpStrike\.cna/ nocase ascii wide
                        $string5 = /\\RdpStrike\\/ nocase ascii wide
                        $string6 = "0xEr3bus/RdpStrike" nocase ascii wide
                        $string7 = "227cc3d2c07ef203c39afe00c81943cf245d626c1efa1b32024d7229604635e5" nocase ascii wide
                        $string8 = "Disabling RDPStrike" nocase ascii wide
                        $string9 = /Injecting\sinto\smstsc\.exe/ nocase ascii wide
                        $string10 = "RDPStrike enabled" nocase ascii wide
                        $string11 = /RdpStrike\.x64\.bin/ nocase ascii wide

    condition:
        any of them
}