import "pe"
rule NoobyProtect_V1XXX_Nooby_20090201: PEiD
{
    strings:
        $a = { 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E ?? 2E ?? 2E ?? 00 }
    condition:
        $a at pe.entry_point

}