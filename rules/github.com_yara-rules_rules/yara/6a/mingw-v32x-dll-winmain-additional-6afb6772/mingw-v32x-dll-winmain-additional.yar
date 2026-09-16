import "pe"
rule MinGW_v32x_Dll_WinMain_additional: PEiD
{
    strings:
        $a = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 00 00 00 5D C2 0C 00 8B 45 0C 57 56 53 8B 5D 10 }
    condition:
        $a at pe.entry_point

}