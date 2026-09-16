import "pe"
rule Shegerd_Dongle_V478_MSCo: PEiD
{
    strings:
        $a = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }
    condition:
        $a at pe.entry_point

}