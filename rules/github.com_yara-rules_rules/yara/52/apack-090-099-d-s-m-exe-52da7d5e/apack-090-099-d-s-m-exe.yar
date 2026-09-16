import "pe"
rule aPack_090_099_d_s_m_EXE: PEiD
{
    strings:
        $a = { 8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B2 80 BD 00 00 33 C9 50 A4 }
    condition:
        $a at pe.entry_point

}