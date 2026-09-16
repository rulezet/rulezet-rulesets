import "pe"
rule AntiDote_14_SE_SIS_Team_additional: PEiD
{
    strings:
        $a = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 }
    condition:
        $a at pe.entry_point

}