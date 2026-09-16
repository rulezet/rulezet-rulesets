import "pe"
rule Gem_VDI_Image_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 01 00 ?? 00 ?? 00 01 }
    condition:
        $a at pe.entry_point

}