import "pe"
rule yodas_Protector_102b_Ashkbiz_Danehkar: PEiD
{
    strings:
        $a = { E8 03 00 00 00 EB 01 }
    condition:
        $a at pe.entry_point

}