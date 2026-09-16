import "pe"
rule Adobe_PhotoShop_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 38 42 50 53 00 01 00 00 }
    condition:
        $a at pe.entry_point

}