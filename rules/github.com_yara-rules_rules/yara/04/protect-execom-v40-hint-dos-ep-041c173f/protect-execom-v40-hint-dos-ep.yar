import "pe"
rule PROTECT_EXECOM_v40_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? E8 ?? ?? 5D 81 ED ?? ?? 33 C0 8E D8 8B F0 BF ?? ?? B9 ?? ?? FC F3 A5 }
    condition:
        $a at pe.entry_point

}