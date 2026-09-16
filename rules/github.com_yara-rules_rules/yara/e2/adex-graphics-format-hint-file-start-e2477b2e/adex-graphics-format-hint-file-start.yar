import "pe"
rule ADEX_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 49 43 54 00 08 ?? 02 }
    condition:
        $a at pe.entry_point

}