import "pe"
rule ACProtect_14x_RISCO_soft_additional: PEiD
{
    strings:
        $a = { 47 53 44 31 02 00 11 00 }
    condition:
        $a at pe.entry_point

}