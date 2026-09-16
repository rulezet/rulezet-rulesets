import "pe"
rule aPack_099_f_m_COM: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 8E C0 59 8E D0 51 BE 00 01 BF 00 01 50 57 FC B2 80 BD 00 01 50 A4 FF D5 73 FB FF D5 41 73 12 FF D5 BB 10 00 72 00 FF D5 12 DB 73 FA 75 00 93 EB 00 B7 01 FF D5 12 FF 72 00 FF D5 72 F6 FF D5 13 C9 FF D5 72 F8 80 EF 03 72 00 8A }
    condition:
        $a at pe.entry_point

}