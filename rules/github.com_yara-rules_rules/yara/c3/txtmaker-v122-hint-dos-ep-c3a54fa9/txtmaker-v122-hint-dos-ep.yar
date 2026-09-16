import "pe"
rule TXTMaker_v122_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? B4 ?? 33 DB CD 10 80 ?? ?? 74 ?? B0 ?? EB ?? 8B }
    condition:
        $a at pe.entry_point

}