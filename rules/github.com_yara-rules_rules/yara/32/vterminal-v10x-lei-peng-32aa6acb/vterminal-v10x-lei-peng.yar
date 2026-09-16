import "pe"
rule Vterminal_V10X_Lei_Peng: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 }
    condition:
        $a at pe.entry_point

}