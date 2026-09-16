import "pe"
rule FSG_110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
        $b = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}