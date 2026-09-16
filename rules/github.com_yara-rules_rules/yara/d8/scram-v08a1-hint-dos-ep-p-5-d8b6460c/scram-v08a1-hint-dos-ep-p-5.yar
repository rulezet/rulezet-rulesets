import "pe"
rule SCRAM_v08a1_Hint_DOS_EP_p_5: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C }
    condition:
        $a at pe.entry_point

}