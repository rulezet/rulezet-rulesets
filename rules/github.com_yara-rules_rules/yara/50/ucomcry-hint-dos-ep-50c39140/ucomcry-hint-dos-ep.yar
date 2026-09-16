import "pe"
rule UCOMCRY_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 60 06 FA E4 64 0C 40 E6 64 B8 ?? ?? 8E C0 26 }
    condition:
        $a at pe.entry_point

}