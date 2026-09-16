import "pe"
rule vfpexeNc_v600_Wang_JianGuo_additional: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }
    condition:
        $a at pe.entry_point

}