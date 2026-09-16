import "pe"
rule Vx_Quake518_additional: PEiD
{
    strings:
        $a = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }
    condition:
        $a at pe.entry_point

}