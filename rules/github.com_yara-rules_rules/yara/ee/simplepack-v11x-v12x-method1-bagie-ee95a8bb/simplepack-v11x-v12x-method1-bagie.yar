import "pe"
rule SimplePack_V11X_V12X_Method1_bagie: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }
    condition:
        $a at pe.entry_point

}