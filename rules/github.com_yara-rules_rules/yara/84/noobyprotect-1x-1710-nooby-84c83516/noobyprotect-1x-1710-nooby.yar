import "pe"
rule NoobyProtect_1x_1710_Nooby: PEiD
{
    strings:
        $a = { ?? ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}