import "pe"
rule AntiDote_1214_SE_DLL_SIS_Team: PEiD
{
    strings:
        $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}