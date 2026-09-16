import "pe"
rule ASPack_211_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 3D 04 00 00 }
    condition:
        $a at pe.entry_point

}