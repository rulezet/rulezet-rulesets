import "pe"
rule Fusion_V10_jaNooNi: PEiD
{
    strings:
        $a = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }
    condition:
        $a at pe.entry_point

}