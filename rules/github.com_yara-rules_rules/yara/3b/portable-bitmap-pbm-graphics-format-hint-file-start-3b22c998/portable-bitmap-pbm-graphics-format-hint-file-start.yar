import "pe"
rule Portable_BitMap_PBM_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 36 0A }
    condition:
        $a at pe.entry_point

}