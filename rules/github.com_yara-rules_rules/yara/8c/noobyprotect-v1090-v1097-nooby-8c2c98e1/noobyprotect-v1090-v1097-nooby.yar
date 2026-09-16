import "pe"
rule NoobyProtect_V1090_V1097_Nooby: PEiD
{
    strings:
        $a = { 53 51 E8 00 00 00 00 8B 1C 24 83 C3 25 33 C9 87 4B FC 83 F9 00 74 06 80 33 ?? 43 E2 FA 83 C4 04 59 5B 9D E9 04 00 00 00 }
    condition:
        $a at pe.entry_point

}