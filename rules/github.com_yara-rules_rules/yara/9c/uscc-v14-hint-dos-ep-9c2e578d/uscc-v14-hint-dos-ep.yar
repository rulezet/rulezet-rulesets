import "pe"
rule USCC_v14_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 60 BB ?? ?? B9 ?? ?? 30 0F 43 E2 ?? 5D F5 F5 FC EF EE FA 4B 9E }
    condition:
        $a at pe.entry_point

}