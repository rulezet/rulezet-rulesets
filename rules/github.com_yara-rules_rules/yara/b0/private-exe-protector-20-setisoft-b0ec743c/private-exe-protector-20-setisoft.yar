import "pe"
rule Private_EXE_Protector_20_SetiSoft: PEiD
{
    strings:
        $a = { 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }
    condition:
        $a at pe.entry_point

}