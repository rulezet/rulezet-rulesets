import "pe"
rule MSLRH_032a_fake_PE_Crypt_102_emadicius: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB }
    condition:
        $a at pe.entry_point

}