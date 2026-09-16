import "pe"
rule PNG_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 89 50 4E 47 0D 0A 1A 0A }
    condition:
        $a at pe.entry_point

}