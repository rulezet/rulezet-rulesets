import "pe"
rule Micrografix_Draw_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 01 FF 02 04 03 02 00 02 }
    condition:
        $a at pe.entry_point

}