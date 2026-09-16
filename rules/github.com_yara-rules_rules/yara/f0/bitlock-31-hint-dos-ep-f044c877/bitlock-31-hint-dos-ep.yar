import "pe"
rule Bitlock_31_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? B4 30 CD 21 3C 03 72 }
    condition:
        $a at pe.entry_point

}