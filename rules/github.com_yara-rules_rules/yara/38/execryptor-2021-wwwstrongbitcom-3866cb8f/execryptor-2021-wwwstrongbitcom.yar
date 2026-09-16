import "pe"
rule EXECryptor_2021_wwwstrongbitcom: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 D0 03 45 F4 8B 18 8B 7E 10 01 D7 03 7D F4 09 DB 0F 84 ?? 00 00 00 F7 C3 00 00 00 80 0F 85 04 00 00 00 8D 5C 13 02 81 E3 FF FF FF ?? 53 FF 75 F8 FF 15 9C ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 07 83 45 F4 04 E9 A6 FF FF FF }
        $b = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}