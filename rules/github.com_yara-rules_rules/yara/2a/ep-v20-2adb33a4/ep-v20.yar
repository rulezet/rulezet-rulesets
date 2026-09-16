import "pe"
rule EP_v20: PEiD
{
    strings:
        $a = { 60 BE ?? B0 42 ?? 8D BE ?? 60 FD FF C7 87 B0 E4 02 ?? 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB ?? ?? ?? }
        $b = { 6A ?? 60 E9 01 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}