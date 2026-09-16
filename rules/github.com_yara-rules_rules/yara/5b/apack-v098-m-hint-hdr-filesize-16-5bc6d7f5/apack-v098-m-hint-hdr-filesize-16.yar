import "pe"
rule aPack_v098_m_Hint_HDR_FILESIZE_16: PEiD
{
    strings:
        $a = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }
    condition:
        $a at pe.entry_point

}