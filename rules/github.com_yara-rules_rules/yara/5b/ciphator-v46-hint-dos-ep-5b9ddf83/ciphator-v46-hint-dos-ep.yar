import "pe"
rule Ciphator_v46_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 93 93 E8 ?? ?? 58 6A 00 0E 68 ?? ?? CF EB }
    condition:
        $a at pe.entry_point

}