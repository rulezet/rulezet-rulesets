import "pe"
rule Maked_by_Grabber_v384_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? FC 8C DB 8C C8 8E D8 8E C0 89 1E ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 }
    condition:
        $a at pe.entry_point

}