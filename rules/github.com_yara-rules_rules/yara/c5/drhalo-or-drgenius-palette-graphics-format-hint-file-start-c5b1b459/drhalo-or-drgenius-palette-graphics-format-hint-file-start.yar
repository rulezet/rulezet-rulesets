import "pe"
rule DrHalo_or_DrGenius_Palette_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 41 48 E3 00 00 00 0A 00 }
    condition:
        $a at pe.entry_point

}