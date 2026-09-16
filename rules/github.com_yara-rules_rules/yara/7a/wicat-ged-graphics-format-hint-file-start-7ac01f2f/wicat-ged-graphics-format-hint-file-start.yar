import "pe"
rule Wicat_GED_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 0D 00 40 00 }
    condition:
        $a at pe.entry_point

}