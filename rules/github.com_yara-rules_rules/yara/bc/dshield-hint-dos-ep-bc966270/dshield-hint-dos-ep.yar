import "pe"
rule DSHIELD_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }
    condition:
        $a at pe.entry_point

}