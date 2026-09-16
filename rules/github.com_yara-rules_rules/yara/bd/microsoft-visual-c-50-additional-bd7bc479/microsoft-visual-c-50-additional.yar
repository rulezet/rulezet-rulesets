import "pe"
rule Microsoft_Visual_C_50_additional: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 }
    condition:
        $a at pe.entry_point

}