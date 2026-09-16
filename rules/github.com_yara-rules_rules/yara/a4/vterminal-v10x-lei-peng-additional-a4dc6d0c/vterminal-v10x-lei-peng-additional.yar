import "pe"
rule Vterminal_V10X_Lei_Peng_additional: PEiD
{
    strings:
        $a = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }
    condition:
        $a at pe.entry_point

}