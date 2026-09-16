import "pe"
rule AntiDote_10_beta_Spy_Instructor: PEiD
{
    strings:
        $a = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 }
    condition:
        $a at pe.entry_point

}