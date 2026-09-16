import "pe"
rule Nullsoft_Install_System_v198: PEiD
{
    strings:
        $a = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }
        $b = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}