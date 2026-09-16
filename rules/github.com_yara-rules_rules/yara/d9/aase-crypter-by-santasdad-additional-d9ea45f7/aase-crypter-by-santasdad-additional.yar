import "pe"
rule Aase_Crypter_by_santasdad_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 }
    condition:
        $a at pe.entry_point

}