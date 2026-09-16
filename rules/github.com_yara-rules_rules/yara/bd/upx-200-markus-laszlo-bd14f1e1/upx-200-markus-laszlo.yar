import "pe"
rule UPX_200_Markus_Laszlo: PEiD
{
    strings:
        $a = { 32 2E 30 30 00 55 50 58 }
    condition:
        $a at pe.entry_point

}