import "pe"
rule Vx_Ncu_Li1688_additional: PEiD
{
    strings:
        $a = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }
    condition:
        $a at pe.entry_point

}