import "pe"
rule Microsoft_C_for_Windows_1: PEiD
{
    strings:
        $a = { 33 ED 55 9A ?? ?? ?? ?? 0B C0 74 }
    condition:
        $a at pe.entry_point

}