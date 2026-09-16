import "pe"
rule Private_EXE_v20a: PEiD
{
    strings:
        $a = { 53 E8 00 00 00 00 5B 8B C3 2D }
        $b = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}