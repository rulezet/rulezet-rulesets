import "pe"
rule TINYPROG_v36_v39_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? EB ?? C3 }
    condition:
        $a at pe.entry_point

}