import "pe"
rule CRYPACK_v30_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 06 1E 8C D8 05 ?? ?? 8E D8 33 DB 0E 07 33 FF BE ?? ?? 8A 07 26 ?? ?? 32 C4 88 07 47 3B FE }
    condition:
        $a at pe.entry_point

}