import "pe"
rule D1S1G_v11_Beta_pp_Scrambled_EXE_D1N_additional: PEiD
{
    strings:
        $a = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 }
    condition:
        $a at pe.entry_point

}