import "pe"
rule Lotus_Graphics_format: PEiD
{
    strings:
        $a = { 01 00 00 00 01 00 08 00 }
    condition:
        $a at pe.entry_point

}