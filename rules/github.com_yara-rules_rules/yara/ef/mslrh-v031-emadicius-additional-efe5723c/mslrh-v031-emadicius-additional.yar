import "pe"
rule MSLRH_V031_emadicius_additional: PEiD
{
    strings:
        $a = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }
    condition:
        $a at pe.entry_point

}