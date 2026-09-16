import "pe"
rule Vx_Paybackdropper_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? B9 ?? ?? B8 ?? ?? BE ?? ?? 49 78 ?? 30 04 86 E0 D3 C8 4E EB }
    condition:
        $a at pe.entry_point

}