import "pe"
rule by_Central_Point_Software_Hint_DOS_EP_p_40: PEiD
{
    strings:
        $a = { 50 51 52 56 57 8B EB 1E 2E }
    condition:
        $a at pe.entry_point

}