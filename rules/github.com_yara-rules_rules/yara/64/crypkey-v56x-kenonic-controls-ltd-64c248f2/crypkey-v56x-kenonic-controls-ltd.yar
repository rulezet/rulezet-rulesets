import "pe"
rule CrypKey_V56X_Kenonic_Controls_Ltd: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }
    condition:
        $a at pe.entry_point

}