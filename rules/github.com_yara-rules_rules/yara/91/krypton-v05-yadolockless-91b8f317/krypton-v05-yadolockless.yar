import "pe"
rule Krypton_v05_yadolockless: PEiD
{
    strings:
        $a = { 54 E8 00 00 00 00 5D 8B C5 81 ED 71 44 ?? 00 2B 85 64 60 ?? 00 EB 43 DF }
    condition:
        $a at pe.entry_point

}