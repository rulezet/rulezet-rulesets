import "pe"
rule XPack_V097_LZRW_JoKo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? 00 9C 60 E8 4D 02 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 44 ?? ?? 00 34 ?? ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}