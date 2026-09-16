import "pe"
rule UPX_v0896_v102_v105_v122_DLL: PEiD
{
    strings:
        $a = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
        $b = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}