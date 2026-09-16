import "pe"
rule Solidshield_Protector_V1X_Solidshield_Technologies: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}