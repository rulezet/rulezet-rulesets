import "pe"
rule Microsoft_C_for_Windows_2_additional: PEiD
{
    strings:
        $a = { 8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89 }
    condition:
        $a at pe.entry_point

}