import "pe"
rule Intel_DCX_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { B1 68 DE 3A 04 10 00 }
    condition:
        $a at pe.entry_point

}