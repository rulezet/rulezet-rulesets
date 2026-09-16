import "pe"
rule AverCryptor_10_os1r1s_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 }
    condition:
        $a at pe.entry_point

}