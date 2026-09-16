import "pe"
rule aPack_098_099_t_EXE: PEiD
{
    strings:
        $a = { 1E 06 0E 1F 0E 07 BE 13 00 BF 00 7F 8B CF FC 57 F3 A4 C3 33 FF BE 00 7F B2 80 BD 00 7F 50 A4 BB 10 00 FF D5 73 F8 FF D5 41 73 0F FF D5 72 24 FF D5 12 DB 73 FA 75 00 93 EB 00 B7 01 FF D5 12 FF 72 00 FF D5 72 F6 FF D5 13 C9 FF D5 72 F8 80 EF }
    condition:
        $a at pe.entry_point

}