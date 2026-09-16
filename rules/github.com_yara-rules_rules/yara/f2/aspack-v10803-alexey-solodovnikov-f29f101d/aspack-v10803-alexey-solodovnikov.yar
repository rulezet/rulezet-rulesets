import "pe"
rule ASPack_v10803_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
    condition:
        $a at pe.entry_point

}