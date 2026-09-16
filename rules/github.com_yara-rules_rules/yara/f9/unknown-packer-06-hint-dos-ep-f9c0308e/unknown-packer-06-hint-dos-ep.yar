import "pe"
rule Unknown_packer_06_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC }
    condition:
        $a at pe.entry_point

}