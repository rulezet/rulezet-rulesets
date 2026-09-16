import "pe"
rule Username_300_EXE: PEiD
{
    strings:
        $a = { FB 2E 8C 1E 22 02 2E 8C 06 3F 02 2E 8B 0E 41 02 2E 8B 1E 43 02 8C C8 2B C1 8B C8 2E 89 1E 1E 02 2E 89 0E 20 02 33 C0 8E D8 06 0E 07 FC 33 F6 BF 1B 03 B9 14 00 F3 A4 07 FA A1 84 00 8B 1E 86 00 A3 0C 00 89 1E 0E 00 8B 16 40 00 8B 1E 42 00 B8 }
    condition:
        $a at pe.entry_point

}