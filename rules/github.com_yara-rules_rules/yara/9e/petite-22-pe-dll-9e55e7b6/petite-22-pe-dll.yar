import "pe"
rule Petite_22_PE_DLL: PEiD
{
    strings:
        $a = { B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 00 00 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A 00 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 }
    condition:
        $a at pe.entry_point

}