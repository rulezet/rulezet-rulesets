import "pe"
rule PE_PACK_10: PEiD
{
    strings:
        $a = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }
        $b = { 74 00 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}