import "pe"
rule Safengine_Shielden_v2160: PEiD
{
    strings:
        $a = { E8 1C 00 00 00 53 61 66 65 6E 67 69 6E 65 20 53 68 69 65 6C 64 65 6E 20 }
    condition:
        $a at pe.entry_point

}