import "pe"
rule Celsius_Crypt_21_Z3r0_additional: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 }
    condition:
        $a at pe.entry_point

}