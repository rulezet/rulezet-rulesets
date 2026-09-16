import "pe"
rule N_Code_01_NEX: PEiD
{
    strings:
        $a = { BB E8 03 00 00 81 C3 E8 03 00 00 B8 05 00 00 00 B9 73 00 00 00 01 C8 83 E8 32 90 90 90 90 6B C0 02 90 68 FF 64 24 F0 90 90 90 90 90 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }
    condition:
        $a at pe.entry_point

}