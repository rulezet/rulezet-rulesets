import "pe"
rule SimplePack_10X_bagie: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }
    condition:
        $a at pe.entry_point

}