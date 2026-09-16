import "pe"
rule UPX_124_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 34 00 55 50 58 }
    condition:
        $a at pe.entry_point

}