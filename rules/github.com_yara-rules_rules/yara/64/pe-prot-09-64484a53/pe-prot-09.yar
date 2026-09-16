import "pe"
rule PE_Prot_09: PEiD
{
    strings:
        $a = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 00 00 00 00 58 83 C0 07 C6 00 C3 EA E8 00 00 00 00 5D 8B D5 81 ED 68 45 40 00 60 8D 9D AC 45 40 00 B9 1D 03 00 00 B2 00 33 C0 02 03 D2 0B E8 0B 00 00 00 0F 21 C7 28 13 EB 02 9A EA 80 33 C3 43 }
    condition:
        $a at pe.entry_point

}