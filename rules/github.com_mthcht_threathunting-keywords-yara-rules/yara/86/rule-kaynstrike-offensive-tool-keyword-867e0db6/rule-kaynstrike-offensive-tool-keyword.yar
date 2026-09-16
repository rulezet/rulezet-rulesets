rule rule_KaynStrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KaynStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KaynStrike_offensive_tool_keyword = /\sKaynStrike\.cna/ nocase ascii wide
                        $string2_KaynStrike_offensive_tool_keyword = /\/include\/KaynStrike\.h/ nocase ascii wide
                        $string3_KaynStrike_offensive_tool_keyword = /\/KaynStrike\.cna/ nocase ascii wide
                        $string4_KaynStrike_offensive_tool_keyword = /\/KaynStrike\.git/ nocase ascii wide
                        $string5_KaynStrike_offensive_tool_keyword = /\/src\/KaynStrike\.c/ nocase ascii wide
                        $string6_KaynStrike_offensive_tool_keyword = /\\include\\KaynStrike\.h/ nocase ascii wide
                        $string7_KaynStrike_offensive_tool_keyword = /\\KAssembly\.x64\.o/ nocase ascii wide
                        $string8_KaynStrike_offensive_tool_keyword = /\\KaynStrike\.cna/ nocase ascii wide
                        $string9_KaynStrike_offensive_tool_keyword = /\\KaynStrike\\src\\/ nocase ascii wide
                        $string10_KaynStrike_offensive_tool_keyword = /\\KaynStrike\-main/ nocase ascii wide
                        $string11_KaynStrike_offensive_tool_keyword = /\\src\\KaynStrike\.c/ nocase ascii wide
                        $string12_KaynStrike_offensive_tool_keyword = "Cracked5pider/KaynStrike" nocase ascii wide
                        $string13_KaynStrike_offensive_tool_keyword = /KaynStrike\.x64\.bin/ nocase ascii wide
                        $string14_KaynStrike_offensive_tool_keyword = /KaynStrike\.x64\.exe/ nocase ascii wide
                        $string15_KaynStrike_offensive_tool_keyword = /WINAPI\sKaynLoader\(/ nocase ascii wide

    condition:
        any of them
}