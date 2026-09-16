import "pe"
rule ASPack_v1061b: PEiD
{
    strings:
        $a = { 60 E8 5D 81 ED B8 03 C5 2B 85 0B DE 89 85 17 DE 80 BD 01 }
        $b = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}