import "pe"
rule aPack_v082_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }
    condition:
        $a at pe.entry_point

}