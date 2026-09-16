import "pe"
rule IBM_PictureMaker_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 ?? C1 ?? 00 ?? ?? ?? ?? 02 00 01 }
    condition:
        $a at pe.entry_point

}