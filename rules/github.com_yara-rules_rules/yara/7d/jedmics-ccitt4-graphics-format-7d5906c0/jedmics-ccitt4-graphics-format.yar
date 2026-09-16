import "pe"
rule JEDMICS_CCITT4_Graphics_format: PEiD
{
    strings:
        $a = { 80 00 00 00 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}