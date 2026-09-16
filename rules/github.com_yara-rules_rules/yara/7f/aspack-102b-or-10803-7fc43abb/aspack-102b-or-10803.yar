import "pe"
rule ASPack_102b_or_10803: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED }
    condition:
        $a at pe.entry_point

}