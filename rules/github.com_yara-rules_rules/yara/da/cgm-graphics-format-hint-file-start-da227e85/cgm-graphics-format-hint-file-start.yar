import "pe"
rule CGM_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 2A 08 48 69 4A 61 61 6B 20 32 }
    condition:
        $a at pe.entry_point

}