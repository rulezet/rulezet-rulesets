import "pe"
rule First_Publisher_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 ?? 00 00 00 ?? 01 }
    condition:
        $a at pe.entry_point

}