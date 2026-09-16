import "pe"
rule Windows_Type_1_font_metric_file_additional: PEiD
{
    strings:
        $a = { 00 01 ?? ?? 00 00 43 6F 70 79 72 69 67 68 74 20 }
    condition:
        $a at pe.entry_point

}