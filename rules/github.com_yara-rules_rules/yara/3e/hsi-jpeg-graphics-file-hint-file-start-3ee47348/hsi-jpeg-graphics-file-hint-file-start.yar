import "pe"
rule HSI_JPEG_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 68 73 69 31 00 00 }
    condition:
        $a at pe.entry_point

}