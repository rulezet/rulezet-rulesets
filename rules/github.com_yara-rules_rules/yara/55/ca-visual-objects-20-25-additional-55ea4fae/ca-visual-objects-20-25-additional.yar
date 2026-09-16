import "pe"
rule CA_Visual_Objects_20_25_additional: PEiD
{
    strings:
        $a = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
    condition:
        $a at pe.entry_point

}