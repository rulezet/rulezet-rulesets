import "pe"
rule Private_EXE_Protector_18_SetiSoft_additional: PEiD
{
    strings:
        $a = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 }
    condition:
        $a at pe.entry_point

}