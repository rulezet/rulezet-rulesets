import "pe"
rule EXE_Stealth_v272_additional: PEiD
{
    strings:
        $a = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }
    condition:
        $a at pe.entry_point

}