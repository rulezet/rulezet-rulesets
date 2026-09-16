import "pe"
rule ASPack_v10802: PEiD
{
    strings:
        $a = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D }
        $b = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}