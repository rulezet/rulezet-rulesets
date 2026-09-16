import "pe"
rule Thinstall_V24X_25X_Jitit: PEiD
{
    strings:
        $a = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 }
    condition:
        $a at pe.entry_point

}