import "pe"
rule ExeShield_Protector_V36_wwwexeshieldcom: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }
    condition:
        $a at pe.entry_point

}