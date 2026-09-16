import "pe"
rule CrypKey_V56X_DLL_Kenonic_Controls_Ltd: PEiD
{
    strings:
        $a = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}