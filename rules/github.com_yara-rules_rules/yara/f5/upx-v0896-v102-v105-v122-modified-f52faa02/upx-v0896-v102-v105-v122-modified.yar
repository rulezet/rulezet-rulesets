import "pe"
rule UPX_v0896_v102_v105_v122_Modified: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB 8A 07 EB B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
        $b = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}