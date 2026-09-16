import "pe"
rule Alpha_BMP_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF FF 00 01 64 00 00 00 }
    condition:
        $a at pe.entry_point

}