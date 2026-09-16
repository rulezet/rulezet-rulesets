import "pe"
rule Vx_Hafen809_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D }
    condition:
        $a at pe.entry_point

}