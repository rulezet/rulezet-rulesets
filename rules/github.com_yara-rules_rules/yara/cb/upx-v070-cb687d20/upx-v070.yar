import "pe"
rule UPX_v070: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 83 CD FF 31 DB 5E 8D BE FA FF 57 66 81 87 81 C6 B3 01 EB 0A 8A 06 46 88 07 47 01 DB 75 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}