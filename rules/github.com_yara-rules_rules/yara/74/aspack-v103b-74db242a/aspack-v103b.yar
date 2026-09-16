import "pe"
rule ASPack_v103b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED CE 3A 44 B8 C8 3A 44 03 C5 2B 85 B5 3E 44 89 85 C1 3E 44 80 BD AC 3E }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}