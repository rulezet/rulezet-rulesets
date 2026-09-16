import "pe"
rule MSVCpp_DLL_v8_typical_OEP_recognized_h_additional: PEiD
{
    strings:
        $a = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? ?? ?? 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 ?? ?? ?? FF 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 ?? ?? ?? FF 83 FE 01 89 45 0C 75 0C 85 C0 75 37 57 50 53 E8 ?? ?? ?? FF 85 F6 74 05 83 FE 03 75 26 57 56 53 E8 ?? ?? ?? FF 85 C0 75 03 21 45 0C 83 7D 0C 00 74 11 A1 ?? ?? ?? ?? 85 C0 74 08 57 56 53 FF D0 89 45 0C 8B 45 0C 5F 5E 5B 5D C2 0C 00 }
    condition:
        $a at pe.entry_point

}