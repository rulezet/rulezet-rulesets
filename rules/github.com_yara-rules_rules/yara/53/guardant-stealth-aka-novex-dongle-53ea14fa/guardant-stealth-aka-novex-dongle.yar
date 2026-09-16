import "pe"
rule Guardant_Stealth_aka_Novex_Dongle: PEiD
{
    strings:
        $a = { 50 53 51 52 57 56 8B 75 1C 8B 3E 8B 5D 08 8A FB 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF }
        $b = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}