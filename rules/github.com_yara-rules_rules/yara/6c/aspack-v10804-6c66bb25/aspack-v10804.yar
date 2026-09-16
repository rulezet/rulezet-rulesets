import "pe"
rule ASPack_v10804: PEiD
{
    strings:
        $a = { A8 03 61 75 08 B8 01 C2 0C 68 C3 8B 85 26 04 8D 8D 3B 04 51 50 FF }
        $b = { 60 E8 41 06 00 00 EB 41 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}