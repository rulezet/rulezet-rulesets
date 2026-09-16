import "pe"
rule Microsoft_Paint_Graphics_format: PEiD
{
    strings:
        $a = { 4C 69 6E 53 }
    condition:
        $a at pe.entry_point

}