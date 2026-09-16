import "pe"
rule aPack_090_099_d_s_EXE: PEiD
{
    strings:
        $a = { 8C CB BA 00 00 03 DA FC 33 F6 33 FF 4B 8E DB 8D 87 00 00 8E C0 B9 08 00 F3 A5 4A 75 EB 8E C3 8E D8 33 FF BE 2E 00 05 00 00 0E 50 6A 00 CB }
    condition:
        $a at pe.entry_point

}