import "pe"
rule CrypKey_V61X_DLL_CrypKey_Canada_Inc_additional: PEiD
{
    strings:
        $a = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }
    condition:
        $a at pe.entry_point

}