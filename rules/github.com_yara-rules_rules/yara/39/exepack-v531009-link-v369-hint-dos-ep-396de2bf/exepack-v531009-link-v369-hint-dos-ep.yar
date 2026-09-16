import "pe"
rule EXEPACK_v531009_LINK_v369_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8B E8 8C C0 }
    condition:
        $a at pe.entry_point

}