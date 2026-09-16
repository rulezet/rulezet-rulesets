import "pe"
rule TXT2COM_Read_A_Matic_v10_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E D8 8C 06 ?? ?? FA 8E D0 BC ?? ?? FB B4 ?? CD 21 A3 ?? ?? 06 50 B4 34 CD 21 }
    condition:
        $a at pe.entry_point

}