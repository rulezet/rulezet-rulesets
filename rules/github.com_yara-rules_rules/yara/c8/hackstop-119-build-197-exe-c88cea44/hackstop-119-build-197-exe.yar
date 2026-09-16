import "pe"
rule HackStop_119_build_197_EXE: PEiD
{
    strings:
        $a = { 56 BE EB 04 5E EB FB 9A 1E 52 B8 4D 30 CD 21 86 C4 3D D6 02 73 02 CD 20 0E 1F 56 BE EB 04 5E EB FB 9A E8 02 00 24 24 5A B4 09 CD 21 56 BE EB 04 5E EB FB 9A EB 02 D8 88 5A 1F 56 BE EB 04 5E EB FB 9A B0 AD E6 64 E8 0E F3 56 BE EB 04 5E EB FB }
    condition:
        $a at pe.entry_point

}