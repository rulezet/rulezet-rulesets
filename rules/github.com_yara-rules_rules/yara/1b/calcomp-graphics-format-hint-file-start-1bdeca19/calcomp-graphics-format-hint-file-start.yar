import "pe"
rule CalComp_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 02 50 0A }
    condition:
        $a at pe.entry_point

}