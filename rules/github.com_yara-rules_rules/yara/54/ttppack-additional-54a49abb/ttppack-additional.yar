import "pe"
rule TTPpack_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 F6 E8 11 00 00 00 8B 64 24 08 64 8F 05 }
    condition:
        $a at pe.entry_point

}