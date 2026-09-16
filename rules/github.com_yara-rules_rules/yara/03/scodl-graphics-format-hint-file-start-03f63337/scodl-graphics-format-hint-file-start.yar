import "pe"
rule Scodl_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { E0 01 ?? 00 ?? ?? 00 }
    condition:
        $a at pe.entry_point

}