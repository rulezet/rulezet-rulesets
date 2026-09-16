import "pe"
rule Krypton_v02_additional: PEiD
{
    strings:
        $a = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }
    condition:
        $a at pe.entry_point

}