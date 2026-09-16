import "pe"
rule UPX_v062_DLL: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }
    condition:
        $a at pe.entry_point

}