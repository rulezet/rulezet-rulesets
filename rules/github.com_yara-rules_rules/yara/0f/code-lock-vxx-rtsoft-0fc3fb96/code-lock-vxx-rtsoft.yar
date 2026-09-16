import "pe"
rule Code_Lock_vxx_RTSoft: PEiD
{
    strings:
        $a = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }
    condition:
        $a at pe.entry_point

}