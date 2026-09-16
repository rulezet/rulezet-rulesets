import "pe"
rule Sharp_GPB_Graphics_format_additional: PEiD
{
    strings:
        $a = { 4D 00 00 00 00 ?? ?? ?? ?? 08 00 00 00 03 00 00 }
    condition:
        $a at pe.entry_point

}