rule Ammyy_Admin
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\aa_nts\.dll/ nocase ascii wide
                        $string2 = /\\AA_v3\.exe/ nocase ascii wide
                        $string3 = /\\AA_v3\.log/ nocase ascii wide
                        $string4 = /\\AMMYY\\access\.log/ nocase ascii wide
                        $string5 = /\\ControlSet001\\Control\\SafeBoot\\Network\\AmmyyAdmin_/ nocase ascii wide
                        $string6 = /\\ProgramData\\AMMYY\\/ nocase ascii wide
                        $string7 = /\\SOFTWARE\\Ammyy\\Admin/ nocase ascii wide
                        $string8 = /AA_v3\.exe.{0,1000}\s\-elevated/ nocase ascii wide
                        $string9 = /AA_v3\.exe.{0,1000}\s\-service\s\-lunch/ nocase ascii wide
                        $string10 = "Ammyy Admin" nocase ascii wide
                        $string11 = "Ammyy LLC" nocase ascii wide
                        $string12 = /AMMYY_Admin\.exe/ nocase ascii wide
                        $string13 = /rl\.ammyy\.com\// nocase ascii wide
                        $string14 = /SPR\/Ammyy\.R/ nocase ascii wide
                        $string15 = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide
                        $string16 = /www\.ammyy\.com\/files\/v/ nocase ascii wide

    condition:
        any of them
}