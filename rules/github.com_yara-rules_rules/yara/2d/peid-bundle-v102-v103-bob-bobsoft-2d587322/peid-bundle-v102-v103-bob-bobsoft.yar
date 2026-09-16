import "pe"
rule PEiD_Bundle_v102_v103_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
    condition:
        $a at pe.entry_point

}