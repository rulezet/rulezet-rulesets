import "pe"
rule RatPacker_Glue_stub: PEiD
{
    strings:
        $a = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }
        $b = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}