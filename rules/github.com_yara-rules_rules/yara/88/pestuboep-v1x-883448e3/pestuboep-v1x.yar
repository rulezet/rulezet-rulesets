import "pe"
rule PeStubOEP_v1x: PEiD
{
    strings:
        $a = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
        $b = { B8 ?? ?? ?? 00 FF E0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}