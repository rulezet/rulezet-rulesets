import "pe"
rule Upack_V01X_V02X_Dwing: PEiD
{
    strings:
        $a = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }
        $b = { BE 88 01 ?? ?? AD 8B F8 95 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}