import "pe"
rule PCPaintPictor_graphics_file_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 34 12 ?? ?? ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}