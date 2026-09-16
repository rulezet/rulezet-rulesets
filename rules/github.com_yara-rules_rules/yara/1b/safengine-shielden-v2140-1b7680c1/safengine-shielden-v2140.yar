import "pe"
rule Safengine_Shielden_v2140: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 53 61 66 65 6E 67 69 6E 65 20 53 68 69 65 6C 64 65 6E 20 76 32 2E 31 2E 34 2E 30 00 }
    condition:
        $a at pe.entry_point

}