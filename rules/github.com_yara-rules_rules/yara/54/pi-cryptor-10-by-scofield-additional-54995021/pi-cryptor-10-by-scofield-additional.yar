import "pe"
rule Pi_Cryptor_10_by_Scofield_additional: PEiD
{
    strings:
        $a = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 ?? ?? ?? ?? 5A 59 59 64 89 10 68 }
    condition:
        $a at pe.entry_point

}