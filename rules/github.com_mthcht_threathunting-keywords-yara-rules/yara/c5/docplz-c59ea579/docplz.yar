rule DocPlz
{
    meta:
        description = "Detection patterns for the tool 'DocPlz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DocPlz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sComunicationC2\.cpp/ nocase ascii wide
                        $string2 = /\/ComunicationC2\.cpp/ nocase ascii wide
                        $string3 = /\/DocPlz\.git/ nocase ascii wide
                        $string4 = /\/DocsPLZ\.cpp/ nocase ascii wide
                        $string5 = /\/DocsPLZ\.exe/ nocase ascii wide
                        $string6 = /\/ServerC2\.cpp/ nocase ascii wide
                        $string7 = /\/ServerC2\.exe/ nocase ascii wide
                        $string8 = /\\ComunicationC2\.cpp/ nocase ascii wide
                        $string9 = /\\DocsPLZ\.cpp/ nocase ascii wide
                        $string10 = /\\DocsPLZ\.exe/ nocase ascii wide
                        $string11 = /\\Persistence\.exe/ nocase ascii wide
                        $string12 = /\\ServerC2\.cpp/ nocase ascii wide
                        $string13 = /\\ServerC2\.exe/ nocase ascii wide
                        $string14 = /\\ServerC2\\ServerC2\./ nocase ascii wide
                        $string15 = "4C3B106C-8782-4374-9459-851749072123" nocase ascii wide
                        $string16 = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" nocase ascii wide
                        $string17 = /DocPlz\-main\.zip/ nocase ascii wide
                        $string18 = /DocsPLZ\\DocsPLZ\./ nocase ascii wide
                        $string19 = "TheD1rkMtr/DocPlz" nocase ascii wide

    condition:
        any of them
}