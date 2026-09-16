import "pe"
rule aPack_073_074_m_EXE: PEiD
{
    strings:
        $a = { 1E 06 8C C8 BA 00 00 03 C2 8B D8 05 00 00 FC 33 F6 33 FF 48 4B 8E C0 8E DB B9 08 00 F3 A5 4A 75 EE 8E D8 8E C3 33 FF 0E BE 32 00 05 00 00 50 6A 00 CB }
    condition:
        $a at pe.entry_point

}