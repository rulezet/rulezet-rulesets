import "pe"
rule Upack_v032_Beta_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5 }
        $b = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}