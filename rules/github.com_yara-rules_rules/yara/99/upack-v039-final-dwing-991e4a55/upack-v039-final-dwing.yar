import "pe"
rule Upack_v039_final_Dwing: PEiD
{
    strings:
        $a = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
        $b = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}