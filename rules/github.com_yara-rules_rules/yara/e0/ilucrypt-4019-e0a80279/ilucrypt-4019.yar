import "pe"
rule iLUCRYPT_4019: PEiD
{
    strings:
        $a = { 8B EC FA C7 46 FE 00 00 4C 4C C3 FB BF 00 0A B8 00 00 2E 31 05 D1 C8 4F 81 FF 00 00 EB 00 73 F2 }
    condition:
        $a at pe.entry_point

}