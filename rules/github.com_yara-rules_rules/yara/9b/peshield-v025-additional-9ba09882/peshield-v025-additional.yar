import "pe"
rule PESHiELD_v025_additional: PEiD
{
    strings:
        $a = { 60 E8 2B 00 00 00 }
    condition:
        $a at pe.entry_point

}