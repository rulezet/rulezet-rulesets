rule Gotato
{
    meta:
        description = "Detection patterns for the tool 'Gotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -p 4644 -n mal" nocase ascii wide
                        $string2 = " Process spawned with stolen token!" nocase ascii wide
                        $string3 = /\/Gotato\.git/ nocase ascii wide
                        $string4 = /\/gotato\.go/ nocase ascii wide
                        $string5 = /\[\+\]\sStole\stoken\sfrom/ nocase ascii wide
                        $string6 = /\\\\\\\\\.\\\\pipe\\\\mal/ nocase ascii wide
                        $string7 = "gotato -m http" nocase ascii wide
                        $string8 = "gotato -m pipe" nocase ascii wide
                        $string9 = /gotato.{0,1000}\s\-n\smal/ nocase ascii wide
                        $string10 = /gotato.{0,1000}\s\-p\s4644/ nocase ascii wide
                        $string11 = /Gotato\-main\./ nocase ascii wide
                        $string12 = /httpntlm\.go/ nocase ascii wide
                        $string13 = /httpntlm\.old/ nocase ascii wide
                        $string14 = "iammaguire/Gotato" nocase ascii wide
                        $string15 = "TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA" nocase ascii wide

    condition:
        any of them
}