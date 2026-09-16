import "pe"
rule Utah_RLE_Graphics_format: PEiD
{
    strings:
        $a = { 52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08 }
    condition:
        $a at pe.entry_point

}