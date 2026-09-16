import "pe"
rule AVHRR_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { D5 C8 00 01 00 03 00 01 }
    condition:
        $a at pe.entry_point

}