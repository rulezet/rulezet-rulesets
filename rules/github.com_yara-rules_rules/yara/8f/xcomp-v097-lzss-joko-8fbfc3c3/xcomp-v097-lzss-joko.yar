import "pe"
rule XComp_V097_LZSS_JoKo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? 00 9C 60 E8 97 03 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? 00 34 }
    condition:
        $a at pe.entry_point

}