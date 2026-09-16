import "pe"
rule XComp_V097_LZRW_JoKo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? 00 9C 60 E8 9B 02 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 34 ?? ?? 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}