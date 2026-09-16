import "pe"
rule NoobyProtect_SE_Public_V1200_Nooby_20090201: PEiD
{
    strings:
        $a = { E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 32 2E 30 2E 30 }
    condition:
        $a at pe.entry_point

}