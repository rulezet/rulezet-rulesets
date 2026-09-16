import "pe"
rule Microsoft_C_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 ?? B8 }
    condition:
        $a at pe.entry_point

}