rule KaynStrike
{
    meta:
        description = "Detection patterns for the tool 'KaynStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sKaynStrike\.cna/ nocase ascii wide
                        $string2 = /\/include\/KaynStrike\.h/ nocase ascii wide
                        $string3 = /\/KaynStrike\.cna/ nocase ascii wide
                        $string4 = /\/KaynStrike\.git/ nocase ascii wide
                        $string5 = /\/src\/KaynStrike\.c/ nocase ascii wide
                        $string6 = /\\include\\KaynStrike\.h/ nocase ascii wide
                        $string7 = /\\KAssembly\.x64\.o/ nocase ascii wide
                        $string8 = /\\KaynStrike\.cna/ nocase ascii wide
                        $string9 = /\\KaynStrike\\src\\/ nocase ascii wide
                        $string10 = /\\KaynStrike\-main/ nocase ascii wide
                        $string11 = /\\src\\KaynStrike\.c/ nocase ascii wide
                        $string12 = "Cracked5pider/KaynStrike" nocase ascii wide
                        $string13 = /KaynStrike\.x64\.bin/ nocase ascii wide
                        $string14 = /KaynStrike\.x64\.exe/ nocase ascii wide
                        $string15 = /WINAPI\sKaynLoader\(/ nocase ascii wide

    condition:
        any of them
}