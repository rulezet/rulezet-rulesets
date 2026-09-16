import "pe"
rule UPX_120_Markus_Laszlo: PEiD
{
    strings:
        $a = { 31 2E 32 30 00 55 50 58 }
    condition:
        $a at pe.entry_point

}