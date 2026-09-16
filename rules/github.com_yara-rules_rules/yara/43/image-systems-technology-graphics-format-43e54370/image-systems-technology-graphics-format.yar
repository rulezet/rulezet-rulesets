import "pe"
rule Image_Systems_Technology_Graphics_format: PEiD
{
    strings:
        $a = { 03 3A ?? ?? 00 ?? 00 00 }
    condition:
        $a at pe.entry_point

}