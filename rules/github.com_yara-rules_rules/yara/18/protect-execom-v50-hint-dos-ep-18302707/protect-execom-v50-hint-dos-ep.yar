import "pe"
rule PROTECT_EXECOM_v50_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E 0E 0E 1F 07 }
    condition:
        $a at pe.entry_point

}