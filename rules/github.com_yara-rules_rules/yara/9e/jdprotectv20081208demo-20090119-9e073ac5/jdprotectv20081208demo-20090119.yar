import "pe"
rule JDProtectV20081208demo_20090119: PEiD
{
    strings:
        $a = { 10 3C 0C 32 54 50 50 83 2D 51 52 B9 E8 ?? 52 2A 10 16 84 01 }
    condition:
        $a at pe.entry_point

}