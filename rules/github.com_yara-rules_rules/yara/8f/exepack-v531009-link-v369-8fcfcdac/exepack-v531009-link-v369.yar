import "pe"
rule EXEPACK_v531009_LINK_v369: PEiD
{
    strings:
        $a = { 8B E8 8C C0 }
    condition:
        $a at pe.entry_point

}