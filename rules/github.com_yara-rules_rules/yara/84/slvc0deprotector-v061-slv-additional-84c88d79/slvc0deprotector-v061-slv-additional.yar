import "pe"
rule SLVc0deProtector_v061_SLV_additional: PEiD
{
    strings:
        $a = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
    condition:
        $a at pe.entry_point

}