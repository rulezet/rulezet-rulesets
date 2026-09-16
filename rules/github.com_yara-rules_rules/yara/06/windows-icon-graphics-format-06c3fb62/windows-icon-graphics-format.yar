import "pe"
rule Windows_Icon_Graphics_format: PEiD
{
    strings:
        $a = { 00 00 01 00 }
    condition:
        $a at pe.entry_point

}