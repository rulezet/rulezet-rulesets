import "pe"
rule Xorer_v10_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? BE ?? ?? 8B FE B9 ?? ?? 33 DB 80 ?? ?? AC 32 C3 AA E2 }
    condition:
        $a at pe.entry_point

}