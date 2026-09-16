import "pe"
rule EXEPACK_v531009_LINK_v369_additional: PEiD
{
    strings:
        $a = { 8B E8 8C C0 }
    condition:
        $a at pe.entry_point

}