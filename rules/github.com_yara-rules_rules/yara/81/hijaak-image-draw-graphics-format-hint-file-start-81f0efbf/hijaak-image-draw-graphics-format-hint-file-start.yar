import "pe"
rule HiJaak_Image_Draw_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 47 53 44 31 02 00 11 00 }
    condition:
        $a at pe.entry_point

}