import "pe"
rule Rec_Small_103: PEiD
{
    strings:
        $a = { 8C D8 1E E8 00 00 83 C0 0F 5D B9 00 00 81 ED EA 03 40 8E D8 2B DB B2 00 00 17 FE C2 43 83 FB 10 75 F6 E2 ED 1F 8C C0 03 C3 2E 01 86 27 04 2E 03 86 2B 04 FA BC 05 00 8E D0 2E 8B A6 29 04 EB 00 EA 01 00 00 00 7E 01 }
    condition:
        $a at pe.entry_point

}