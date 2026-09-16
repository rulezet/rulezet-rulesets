import "pe"
rule US_Patent_Image_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 55 53 20 50 54 4F 20 00 }
    condition:
        $a at pe.entry_point

}