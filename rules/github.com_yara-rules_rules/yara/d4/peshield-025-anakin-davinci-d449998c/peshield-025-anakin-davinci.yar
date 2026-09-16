import "pe"
rule PESHiELD_025_ANAKiN_DaVinci: PEiD
{
    strings:
        $a = { 60 E8 2B 00 00 00 }
    condition:
        $a at pe.entry_point

}