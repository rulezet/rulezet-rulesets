import "pe"
rule ASPack_v10801: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 BB 10 44 03 DD 2B }
        $b = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}