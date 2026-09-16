import "pe"
rule Krypton_v05: PEiD
{
    strings:
        $a = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
    condition:
        $a at pe.entry_point

}