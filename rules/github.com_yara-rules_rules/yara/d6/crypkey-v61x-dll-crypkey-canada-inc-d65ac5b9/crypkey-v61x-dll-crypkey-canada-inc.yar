import "pe"
rule CrypKey_V61X_DLL_CrypKey_Canada_Inc: PEiD
{
    strings:
        $a = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}