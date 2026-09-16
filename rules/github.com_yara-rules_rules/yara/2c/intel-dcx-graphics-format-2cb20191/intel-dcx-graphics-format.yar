import "pe"
rule Intel_DCX_Graphics_format: PEiD
{
    strings:
        $a = { B1 68 DE 3A 04 10 00 }
    condition:
        $a at pe.entry_point

}