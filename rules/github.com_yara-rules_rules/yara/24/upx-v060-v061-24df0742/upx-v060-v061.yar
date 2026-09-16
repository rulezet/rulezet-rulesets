import "pe"
rule UPX_v060_v061: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 F0 01 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 }
        $b = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}