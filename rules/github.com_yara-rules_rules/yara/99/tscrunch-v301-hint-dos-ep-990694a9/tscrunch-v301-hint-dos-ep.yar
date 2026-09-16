import "pe"
rule TSCRUNCH_v301_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 06 1E 55 57 56 52 51 53 50 16 1F 0E 07 8B F4 }
    condition:
        $a at pe.entry_point

}