import "pe"
rule CorelDraw_8_CDR_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 52 38 }
    condition:
        $a at pe.entry_point

}