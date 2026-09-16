import "pe"
rule Jovian_VI_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 56 49 ?? ?? ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}