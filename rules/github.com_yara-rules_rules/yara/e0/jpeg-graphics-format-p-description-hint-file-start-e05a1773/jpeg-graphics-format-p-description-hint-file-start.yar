import "pe"
rule JPEG_Graphics_format_p_description_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF D8 FF FE 00 27 }
    condition:
        $a at pe.entry_point

}