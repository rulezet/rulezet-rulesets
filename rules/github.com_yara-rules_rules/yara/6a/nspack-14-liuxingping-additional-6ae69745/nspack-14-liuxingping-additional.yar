import "pe"
rule NsPack_14_Liuxingping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }
    condition:
        $a at pe.entry_point

}