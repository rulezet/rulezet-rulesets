import "pe"
rule ASPack_v211b: PEiD
{
    strings:
        $a = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 59 }
        $b = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}