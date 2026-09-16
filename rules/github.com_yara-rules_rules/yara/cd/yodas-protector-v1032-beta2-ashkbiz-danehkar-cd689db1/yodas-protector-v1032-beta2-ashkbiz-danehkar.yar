import "pe"
rule Yodas_Protector_v1032_Beta2_Ashkbiz_Danehkar: PEiD
{
    strings:
        $a = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }
    condition:
        $a at pe.entry_point

}