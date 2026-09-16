import "pe"
rule Vx_Trivial25_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }
    condition:
        $a at pe.entry_point

}