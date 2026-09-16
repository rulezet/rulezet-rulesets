import "pe"
rule Packanoid_Arkanoid_additional: PEiD
{
    strings:
        $a = { BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 }
    condition:
        $a at pe.entry_point

}