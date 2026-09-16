import "pe"
rule Possibly_PCX_graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 0A ?? 01 }
    condition:
        $a at pe.entry_point

}