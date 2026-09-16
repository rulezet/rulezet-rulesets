import "pe"
rule Private_exe_Protector_20_SetiSoft_Team: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}