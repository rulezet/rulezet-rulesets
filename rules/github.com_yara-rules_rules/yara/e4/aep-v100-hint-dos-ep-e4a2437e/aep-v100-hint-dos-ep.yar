import "pe"
rule AEP_v100_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? E4 21 2E ?? ?? ?? 33 C0 8B D8 5D B9 ?? ?? 50 B8 ?? ?? E6 21 0F A9 E6 ?? 53 }
    condition:
        $a at pe.entry_point

}