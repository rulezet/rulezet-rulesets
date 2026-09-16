import "pe"
rule EPW_120_COM: PEiD
{
    strings:
        $a = { 06 57 1E 56 55 52 51 53 50 BB 03 00 81 C3 00 01 2E 8B 07 8C CB 03 C3 05 10 00 50 B8 F3 00 50 CB 8C C0 05 10 00 8E C0 05 05 00 8E D8 2E 8B 0E 00 00 2B F6 2B FF FC F3 A4 0E 1F BA 20 00 B4 09 CD 21 BB 00 00 B9 10 00 B8 20 09 CD 10 BA 0E 00 B4 }
    condition:
        $a at pe.entry_point

}