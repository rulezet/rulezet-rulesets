import "pe"
rule ASPack_v10804_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}