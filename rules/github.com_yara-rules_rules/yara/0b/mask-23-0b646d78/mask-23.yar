import "pe"
rule Mask_23: PEiD
{
    strings:
        $a = { 55 57 CD 03 FC 4D 41 53 4B FA 8B EC 83 6E 06 03 FF 76 06 5D 49 E8 00 00 5B 81 EB A6 05 50 D6 51 52 56 }
    condition:
        $a at pe.entry_point

}