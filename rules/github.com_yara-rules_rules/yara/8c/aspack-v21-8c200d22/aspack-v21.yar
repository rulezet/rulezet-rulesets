import "pe"
rule ASPack_v21: PEiD
{
    strings:
        $a = { 60 E9 3D }
        $b = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}