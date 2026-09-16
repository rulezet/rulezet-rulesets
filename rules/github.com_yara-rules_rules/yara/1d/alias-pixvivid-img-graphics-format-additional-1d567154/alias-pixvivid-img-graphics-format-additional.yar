import "pe"
rule Alias_PIXVivid_IMG_Graphics_format_additional: PEiD
{
    strings:
        $a = { 00 00 ?? ?? 00 18 ?? ?? ?? ?? 01 }
    condition:
        $a at pe.entry_point

}