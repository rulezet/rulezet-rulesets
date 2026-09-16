import "pe"
rule Armadillo_V500_V5X_Dll_Silicon_Realms_Toolworks: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 75 05 E8 ?? ?? ?? ?? FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ?? ?? ?? ?? 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 }
    condition:
        $a at pe.entry_point

}