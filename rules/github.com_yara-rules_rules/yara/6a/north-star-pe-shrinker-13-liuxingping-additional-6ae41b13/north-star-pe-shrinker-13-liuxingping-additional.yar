import "pe"
rule North_Star_PE_Shrinker_13_Liuxingping_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }
    condition:
        $a at pe.entry_point

}