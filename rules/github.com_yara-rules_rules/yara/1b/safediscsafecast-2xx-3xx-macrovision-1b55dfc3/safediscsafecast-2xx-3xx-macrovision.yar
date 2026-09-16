import "pe"
rule SafeDiscSafeCast_2xx_3xx_Macrovision: PEiD
{
    strings:
        $a = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C }
    condition:
        $a at pe.entry_point

}