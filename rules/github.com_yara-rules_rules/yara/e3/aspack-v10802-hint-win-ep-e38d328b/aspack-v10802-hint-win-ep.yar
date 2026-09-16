import "pe"
rule ASPack_v10802_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}