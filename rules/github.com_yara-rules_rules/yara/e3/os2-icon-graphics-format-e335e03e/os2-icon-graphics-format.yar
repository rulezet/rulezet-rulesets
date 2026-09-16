import "pe"
rule OS2_Icon_Graphics_format: PEiD
{
    strings:
        $a = { 43 49 4E 00 00 00 }
    condition:
        $a at pe.entry_point

}