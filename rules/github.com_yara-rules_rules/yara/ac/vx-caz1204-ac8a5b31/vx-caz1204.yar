import "pe"
rule Vx_Caz1204: PEiD
{
    strings:
        $a = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }
    condition:
        $a at pe.entry_point

}