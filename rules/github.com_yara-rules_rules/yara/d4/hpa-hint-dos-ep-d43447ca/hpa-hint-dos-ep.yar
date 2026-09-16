import "pe"
rule HPA_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3 }
    condition:
        $a at pe.entry_point

}