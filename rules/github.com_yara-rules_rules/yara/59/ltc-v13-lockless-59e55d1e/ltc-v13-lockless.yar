import "pe"
rule LTC_v13_lockless: PEiD
{
    strings:
        $a = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }
    condition:
        $a at pe.entry_point

}