import "pe"
rule DIET_v144_v145f_Hint_DOS_EP: PEiD
{
    strings:
        $a = { F9 9C EB }
    condition:
        $a at pe.entry_point

}