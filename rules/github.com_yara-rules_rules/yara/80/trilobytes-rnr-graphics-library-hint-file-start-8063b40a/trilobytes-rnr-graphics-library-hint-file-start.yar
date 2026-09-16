import "pe"
rule Trilobytes_RNR_graphics_library_Hint_FILE_START: PEiD
{
    strings:
        $a = { 84 10 ?? ?? ?? ?? ?? ?? ?? 10 }
    condition:
        $a at pe.entry_point

}