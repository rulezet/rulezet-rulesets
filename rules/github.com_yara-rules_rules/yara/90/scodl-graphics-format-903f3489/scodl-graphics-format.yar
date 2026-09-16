import "pe"
rule Scodl_Graphics_format: PEiD
{
    strings:
        $a = { E0 01 ?? 00 ?? ?? 00 }
    condition:
        $a at pe.entry_point

}