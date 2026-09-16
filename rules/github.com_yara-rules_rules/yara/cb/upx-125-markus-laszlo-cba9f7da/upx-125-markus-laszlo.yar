import "pe"
rule UPX_125_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 35 00 55 50 58 }
    condition:
        $a at pe.entry_point

}