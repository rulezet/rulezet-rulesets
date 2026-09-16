import "pe"
rule ASPack_v105b: PEiD
{
    strings:
        $a = { 90 75 ?? }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}