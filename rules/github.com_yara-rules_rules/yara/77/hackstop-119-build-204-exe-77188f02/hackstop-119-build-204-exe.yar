import "pe"
rule HackStop_119_build_204_EXE: PEiD
{
    strings:
        $a = { 50 B8 EB 04 58 EB FB 9A 9C 1E 52 B4 30 CD 21 86 C4 3D D6 02 73 02 CD 20 0E 1F 50 B8 EB 04 58 EB FB 9A E8 02 00 24 24 5A B4 09 CD 21 50 B8 EB 04 58 EB FB 9A EB 02 D8 88 5A 1F 50 B8 EB 04 58 EB FB 9A B0 AD E6 64 58 25 80 00 8C DB 50 B8 EB 04 }
    condition:
        $a at pe.entry_point

}