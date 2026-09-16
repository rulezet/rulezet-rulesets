import "pe"
rule Private_exe_Protector_V18_SetiSoft_Team: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
    condition:
        $a at pe.entry_point

}