import "pe"
rule First_Publisher_Graphics_format_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { 00 00 ?? 01 00 00 ?? 02 }
    condition:
        $a at pe.entry_point

}