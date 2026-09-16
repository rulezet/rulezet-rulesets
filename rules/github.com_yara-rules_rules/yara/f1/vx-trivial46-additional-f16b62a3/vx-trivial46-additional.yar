import "pe"
rule Vx_Trivial46_additional: PEiD
{
    strings:
        $a = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }
    condition:
        $a at pe.entry_point

}