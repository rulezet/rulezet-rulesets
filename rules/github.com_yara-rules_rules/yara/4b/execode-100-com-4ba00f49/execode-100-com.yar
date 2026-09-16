import "pe"
rule ExeCode_100_COM: PEiD
{
    strings:
        $a = { 8B E8 BA 4C 01 B4 09 CD 21 2E A1 09 01 8C C3 03 C3 B1 02 2E 8B 1E 0F 01 F7 C3 03 00 74 03 83 C3 03 D3 EB 2E 89 1E 19 01 BE 09 01 BF F0 01 B9 09 00 F3 A5 03 C3 05 2D 00 8E C0 05 0E 00 03 C3 FA 8E D0 BC 00 02 FB 1E 8C D8 05 1F 00 8E D8 2E 8B }
    condition:
        $a at pe.entry_point

}