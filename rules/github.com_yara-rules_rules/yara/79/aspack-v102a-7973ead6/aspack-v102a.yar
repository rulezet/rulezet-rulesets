import "pe"
rule ASPack_v102a: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED 96 78 43 B8 90 78 43 03 C5 2B 85 7D 7C 43 89 85 89 7C 43 80 BD 74 7C }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}