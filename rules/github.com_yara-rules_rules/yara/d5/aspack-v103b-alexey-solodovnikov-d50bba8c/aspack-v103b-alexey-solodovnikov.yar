import "pe"
rule ASPack_v103b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
    condition:
        $a at pe.entry_point

}