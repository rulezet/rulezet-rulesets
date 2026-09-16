import "pe"
rule xPEP_03x_xIkUg: PEiD
{
    strings:
        $a = { 55 53 56 51 52 57 E8 16 00 00 00 }
    condition:
        $a at pe.entry_point

}