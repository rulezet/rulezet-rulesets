import "pe"
rule ARJ_SFX_Custom: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 66 9C 60 50 8D 90 5C 01 00 00 68 00 00 40 00 83 3A 00 0F 84 C6 C1 FF FF 8B 04 24 8B 0A 0F BA F1 1F 73 13 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB D9 83 C2 10 8B 5A }
        $b = { 60 BE 15 F0 40 00 8D BE EB 1F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}