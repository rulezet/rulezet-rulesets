import "pe"
rule modified_HACKSTOP_v111f_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8 }
    condition:
        $a at pe.entry_point

}