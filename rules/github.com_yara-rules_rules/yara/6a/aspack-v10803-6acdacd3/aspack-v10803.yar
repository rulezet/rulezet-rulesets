import "pe"
rule ASPack_v10803: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 }
        $b = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}