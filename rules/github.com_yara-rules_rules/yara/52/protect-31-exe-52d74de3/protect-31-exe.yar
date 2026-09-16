import "pe"
rule Protect_31_EXE: PEiD
{
    strings:
        $a = { 2E A3 00 00 8C D8 2E A3 02 00 8C C8 2E A3 06 00 2E 89 2E 04 00 33 C0 8E D8 FA FC BE 04 00 0E 07 BF 08 00 A5 A5 BE 0C 00 A5 A5 1E 07 BE 04 00 BF 0C 00 B8 D4 01 AB 87 FE AB 2E A1 06 00 87 FE AB 87 F7 AB 89 E0 8C D3 0E 17 BC 85 00 B9 CD 01 4C }
    condition:
        $a at pe.entry_point

}