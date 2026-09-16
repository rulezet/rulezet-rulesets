import "pe"
rule MicroDog_Win32Shell_V4093_Dll_SafeNet: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 19 FF FF FF E9 AF EC FF FF 90 90 90 90 90 55 8B EC 83 EC 18 53 56 57 8B 45 08 8B 00 C1 E8 10 89 45 FC 8B 45 08 8B 00 25 FF FF 00 00 89 45 F8 C7 45 F4 5A 01 00 00 C7 45 EC 35 4E 00 00 8B 45 F4 0F AF 45 F8 25 FF FF 00 00 89 45 F0 83 7D }
    condition:
        $a at pe.entry_point

}