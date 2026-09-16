import "pe"
rule Krypton_v04_yadolockless: PEiD
{
    strings:
        $a = { 54 E8 00 00 00 00 5D 8B C5 81 ED 61 34 ?? 00 2B 85 60 37 ?? 00 83 E8 06 }
    condition:
        $a at pe.entry_point

}