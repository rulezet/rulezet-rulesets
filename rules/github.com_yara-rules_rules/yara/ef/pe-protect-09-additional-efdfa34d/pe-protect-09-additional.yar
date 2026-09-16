import "pe"
rule PE_PROTECT_09_additional: PEiD
{
    strings:
        $a = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }
    condition:
        $a at pe.entry_point

}