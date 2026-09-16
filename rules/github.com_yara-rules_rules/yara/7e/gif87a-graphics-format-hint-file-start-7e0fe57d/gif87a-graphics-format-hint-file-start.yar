import "pe"
rule GIF87a_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 47 49 46 38 37 61 }
    condition:
        $a at pe.entry_point

}