import "pe"
rule Krypton_v05_additional: PEiD
{
    strings:
        $a = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
    condition:
        $a at pe.entry_point

}