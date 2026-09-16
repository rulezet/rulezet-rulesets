import "pe"
rule Portable_BitMap_PBM_Graphics_format: PEiD
{
    strings:
        $a = { 50 36 0A }
    condition:
        $a at pe.entry_point

}