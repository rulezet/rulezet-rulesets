import "pe"
rule WordPerfect_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF 57 50 43 10 00 00 00 }
    condition:
        $a at pe.entry_point

}