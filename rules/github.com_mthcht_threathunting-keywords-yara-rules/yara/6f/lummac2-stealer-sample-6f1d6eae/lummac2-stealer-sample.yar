rule LummaC2_Stealer_sample
{
    meta:
        description = "Detection patterns for the tool 'LummaC2-Stealer-sample' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LummaC2-Stealer-sample"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "%appdaedx765ta%/Binaedx765nce" nocase ascii wide
                        $string2 = "%appdedx765ata%/Eledx765ectrum" nocase ascii wide
                        $string3 = "%appdedx765ata%/Etheedx765reum" nocase ascii wide
                        $string4 = "%localaedx765ppdata%" nocase ascii wide
                        $string5 = "%loedx765calappedx765data" nocase ascii wide
                        $string6 = "%userproedx765file%" nocase ascii wide
                        $string7 = /\.edx765txt/ nocase ascii wide
                        $string8 = /\\\\Edge\\\\Usedx765er\sData/ nocase ascii wide
                        $string9 = /\\\\Locedx765al\sStaedx765te/ nocase ascii wide
                        $string10 = /apedx765p\-stoedx765re\.jsedx765on/ nocase ascii wide
                        $string11 = "Binedx765ance Chaedx765in Waledx765let" nocase ascii wide
                        $string12 = /Brex765ave\-Broedx765wser\\\\Usedx765er\sData/ nocase ascii wide
                        $string13 = /Chredx765ome\\\\Usedx765er\sDatedx765a/ nocase ascii wide
                        $string14 = /Chroedx765mium\\\\Useedx765r\sData/ nocase ascii wide
                        $string15 = "Extedx765ensioedx765ns/" nocase ascii wide
                        $string16 = "ExtractFileInfoViaNTDLL" nocase ascii wide
                        $string17 = /ExtractFirefoxProfileData\(/ nocase ascii wide
                        $string18 = "Importedx765ant Fileedx765s/Proedx765file" nocase ascii wide
                        $string19 = "keystedx765ore" nocase ascii wide
                        $string20 = /Komedx765eta\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
                        $string21 = "Locedx765al Extensedx765ion Settinedx765gs" nocase ascii wide
                        $string22 = "Loedx765gin Daedx765ta" nocase ascii wide
                        $string23 = "Logedx765in Daedx765ta Foedx765r Accedx765ount" nocase ascii wide
                        $string24 = "Meedx765taMaedx765sk" nocase ascii wide
                        $string25 = "Micedx765rosoft" nocase ascii wide
                        $string26 = /Moedx765zilla\\\\Firedx765efox\\\\Profedx765iles/ nocase ascii wide
                        $string27 = "Moziedx765lla Firefedx765ox" nocase ascii wide
                        $string28 = /Netwedx765ork\\\\Cookedx765ies/ nocase ascii wide
                        $string29 = /Opedx765era\sNeoedx765n\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
                        $string30 = /Opedx765era\sSoftwedx765are\\\\Opedx765era\sGX\sStaedx765ble/ nocase ascii wide
                        $string31 = /Opeedx765ra\sSoftedx765ware\\\\Opedx765era\sStaedx765ble/ nocase ascii wide
                        $string32 = "resutlStrBrwsrOfshit" nocase ascii wide
                        $string33 = "Ronedx765in Walledx765et" nocase ascii wide
                        $string34 = "Troedx765nLiedx765nk" nocase ascii wide
                        $string35 = /Viedx765valdi\\\\Usedx765er\sData/ nocase ascii wide
                        $string36 = "Walledx765ets/Binanedx765ce" nocase ascii wide
                        $string37 = "Walledx765ets/Eleedx765ctrum" nocase ascii wide
                        $string38 = "Walledx765ets/Ethedx765ereum" nocase ascii wide
                        $string39 = "Wedx765eb Daedx765ta" nocase ascii wide

    condition:
        any of them
}