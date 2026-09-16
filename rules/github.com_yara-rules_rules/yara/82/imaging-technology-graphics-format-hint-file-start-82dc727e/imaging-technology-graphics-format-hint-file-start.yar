import "pe"
rule Imaging_Technology_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 4D 00 00 }
    condition:
        $a at pe.entry_point

}