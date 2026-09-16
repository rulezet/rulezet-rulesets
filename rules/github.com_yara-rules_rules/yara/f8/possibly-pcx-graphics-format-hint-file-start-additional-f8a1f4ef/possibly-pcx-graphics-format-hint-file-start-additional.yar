import "pe"
rule Possibly_PCX_graphics_format_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { 10 ?? 01 }
    condition:
        $a at pe.entry_point

}