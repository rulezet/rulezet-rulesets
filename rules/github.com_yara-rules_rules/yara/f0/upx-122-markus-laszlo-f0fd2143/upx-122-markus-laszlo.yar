import "pe"
rule UPX_122_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 32 00 55 50 58 }
    condition:
        $a at pe.entry_point

}