import "pe"
rule Neolite_v20: PEiD
{
    strings:
        $a = { 9E 37 ?? ?? 48 6F 4C }
        $b = { E9 A6 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}