import "pe"
rule Code_Lock_vxx_additional: PEiD
{
    strings:
        $a = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }
    condition:
        $a at pe.entry_point

}