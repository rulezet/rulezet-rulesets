import "pe"
rule ASPack_v10801_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
        $b = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}