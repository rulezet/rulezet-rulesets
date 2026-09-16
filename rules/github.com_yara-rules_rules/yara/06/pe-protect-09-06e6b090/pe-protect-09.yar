import "pe"
rule PE_PROTECT_09: PEiD
{
    strings:
        $a = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }
        $b = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}