import "pe"
rule UPX_v071_DLL_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }
    condition:
        $a at pe.entry_point

}