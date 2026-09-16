import "pe"
rule ASPack_104b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? 00 B8 ?? ?? ?? 00 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? 00 80 BD 08 9D ?? 00 00 }
    condition:
        $a at pe.entry_point

}