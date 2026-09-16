import "pe"
rule aPack_090_m_p_COM: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 8E C0 59 8E D0 51 BE 00 01 BF 00 01 50 57 FC B2 80 BD 00 01 50 A4 FF D5 73 FB FF D5 73 14 FF D5 73 00 33 DB B1 04 FF D5 13 DB E2 FA 75 00 93 AA EB E4 E8 00 00 49 E2 07 5B 53 E8 00 00 EB 00 49 AC 8A E1 93 E8 }
    condition:
        $a at pe.entry_point

}