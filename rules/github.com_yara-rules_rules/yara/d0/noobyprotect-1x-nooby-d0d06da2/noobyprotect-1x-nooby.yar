import "pe"
rule NoobyProtect_1x_Nooby: PEiD
{
    strings:
        $a = { ?? 18 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E }
    condition:
        $a at pe.entry_point

}