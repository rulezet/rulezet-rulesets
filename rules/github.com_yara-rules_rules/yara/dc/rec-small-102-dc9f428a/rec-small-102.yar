import "pe"
rule Rec_Small_102: PEiD
{
    strings:
        $a = { 8C D8 1E E8 00 00 83 C0 0F 5D B9 00 00 81 ED BA 03 40 8E D8 2B DB B2 00 00 17 FE C2 43 83 FB 10 75 F6 E2 ED 1F 8C C0 03 C3 2E 01 86 F5 03 2E 03 86 F9 03 FA 2E 8B A6 F7 03 8E D0 FB EB 00 EA }
    condition:
        $a at pe.entry_point

}