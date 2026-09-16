rule BadRentdrv2
{
    meta:
        description = "Detection patterns for the tool 'BadRentdrv2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadRentdrv2"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /A\sVariant\sOf\sWin64\/KillProc\.V/ nocase ascii wide
                        $string2 = /Exploitable\sHangzhou\sRentDrv\sDriver\s\(PUA\)/ nocase ascii wide
                        $string3 = /PUA\.Win64\.Rentdrv\./ nocase ascii wide
                        $string4 = /Win64\/RentDrv\.A\sPotentially\sUnsafe/ nocase ascii wide

    condition:
        any of them
}