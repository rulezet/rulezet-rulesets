import "pe"
rule EXE_Packer_v70_by_TurboPower_Software_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }
    condition:
        $a at pe.entry_point

}