import "pe"
rule PESHiELD_v02_v02b_v02b2_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
    condition:
        $a at pe.entry_point

}