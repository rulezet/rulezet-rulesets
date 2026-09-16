import "pe"
rule PROTECT_EXECOM_v50: PEiD
{
    strings:
        $a = { 1E 0E 0E 1F 07 }
    condition:
        $a at pe.entry_point

}