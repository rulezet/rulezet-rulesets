import "pe"
rule LZEXE_v091_v100a_3_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 06 0E 1F 8B 0E }
    condition:
        $a at pe.entry_point

}