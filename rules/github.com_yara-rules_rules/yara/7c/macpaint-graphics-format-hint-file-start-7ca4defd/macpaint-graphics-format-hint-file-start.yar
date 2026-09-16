import "pe"
rule MacPaint_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 00 02 FF FF FF FF }
    condition:
        $a at pe.entry_point

}