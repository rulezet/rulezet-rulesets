import "pe"
rule FreeJoiner_153_Stub_engine_171_GlOFF_additional: PEiD
{
    strings:
        $a = { 86 D6 90 86 F2 B9 93 60 08 FE 90 86 D6 90 86 F2 B9 9D 13 45 01 86 D6 90 86 F2 81 C2 93 60 08 FE 33 C9 B9 30 74 4D FF 86 D6 90 86 F2 33 C9 C7 05 B4 17 40 00 00 00 00 00 90 68 00 01 00 00 68 D1 17 40 00 6A 00 E8 CE 02 00 00 90 33 C9 86 D6 90 86 F2 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 D1 17 40 00 E8 9E 02 00 00 A3 CD 17 40 00 86 D6 }
    condition:
        $a at pe.entry_point

}