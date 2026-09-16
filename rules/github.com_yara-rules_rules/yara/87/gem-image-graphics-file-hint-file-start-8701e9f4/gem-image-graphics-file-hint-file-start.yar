import "pe"
rule GEM_Image_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 01 00 08 00 04 00 02 }
    condition:
        $a at pe.entry_point

}