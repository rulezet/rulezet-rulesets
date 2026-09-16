import "pe"
rule WATCOM_CCpp: PEiD
{
    strings:
        $a = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F }
        $b = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}