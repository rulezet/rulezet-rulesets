import "pe"
rule ASPack_v2xx_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
    condition:
        $a at pe.entry_point

}