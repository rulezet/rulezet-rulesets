import "pe"
rule ASPack_v211d: PEiD
{
    strings:
        $a = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81 }
        $b = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}