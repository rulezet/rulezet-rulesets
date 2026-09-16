import "pe"
rule Vx_Involuntary1349_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }
    condition:
        $a at pe.entry_point

}