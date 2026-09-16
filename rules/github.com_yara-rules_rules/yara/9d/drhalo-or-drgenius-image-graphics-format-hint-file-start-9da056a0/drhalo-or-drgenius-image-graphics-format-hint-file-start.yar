import "pe"
rule DrHalo_or_DrGenius_Image_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 3A 03 00 00 }
    condition:
        $a at pe.entry_point

}