import "pe"
rule Thinstall_Embedded_V19X_Jitit_Sign_by_fly: PEiD
{
    strings:
        $a = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }
    condition:
        $a at pe.entry_point

}