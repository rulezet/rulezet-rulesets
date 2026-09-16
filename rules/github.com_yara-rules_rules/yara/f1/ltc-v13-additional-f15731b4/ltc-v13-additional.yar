import "pe"
rule LTC_v13_additional: PEiD
{
    strings:
        $a = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }
    condition:
        $a at pe.entry_point

}