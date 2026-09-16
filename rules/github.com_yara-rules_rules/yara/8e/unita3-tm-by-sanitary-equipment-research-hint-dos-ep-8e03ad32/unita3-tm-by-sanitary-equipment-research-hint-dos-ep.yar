import "pe"
rule UNITA3_tm_by_Sanitary_Equipment_Research_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A 3E }
    condition:
        $a at pe.entry_point

}