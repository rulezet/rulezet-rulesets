import "pe"
rule Unknown_packer_08_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F }
    condition:
        $a at pe.entry_point

}