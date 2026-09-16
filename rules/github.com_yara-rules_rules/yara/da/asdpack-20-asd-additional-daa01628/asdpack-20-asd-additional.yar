import "pe"
rule ASDPack_20_asd_additional: PEiD
{
    strings:
        $a = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
    condition:
        $a at pe.entry_point

}