import "pe"
rule InterLok_V5X_PACE_Anti_Piracy_SignByfly_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC A4 00 00 00 53 56 33 F6 57 39 35 ?? ?? ?? ?? 75 53 8D 45 DC 6A 1C 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 05 8B 45 E0 EB 22 8B 7D 08 6A 02 57 FF 15 ?? ?? ?? ?? 85 C0 75 0B 66 81 3F 4D 5A 75 04 8B C7 EB 07 56 FF 15 ?? ?? ?? ?? A3 }
    condition:
        $a at pe.entry_point

}