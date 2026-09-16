import "pe"
rule Zortech_C_200_2: PEiD
{
    strings:
        $a = { FC BE 00 01 B9 FB 02 8B 3E F9 03 57 03 F9 81 C7 00 01 57 F3 A4 5F 81 C7 35 00 FF E7 BE FB 03 59 BF 00 01 57 F3 A4 C3 9C 50 51 52 56 57 55 1E FC 2E C7 06 00 00 FF FF 2E C7 06 06 00 12 00 8C C8 3D 00 A0 72 10 8E D8 BA CD 02 0E 1F B4 09 CD 21 }
    condition:
        $a at pe.entry_point

}