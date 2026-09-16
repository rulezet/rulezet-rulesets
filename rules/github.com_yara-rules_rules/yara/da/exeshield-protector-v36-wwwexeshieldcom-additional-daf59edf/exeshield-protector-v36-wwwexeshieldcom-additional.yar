import "pe"
rule ExeShield_Protector_V36_wwwexeshieldcom_additional: PEiD
{
    strings:
        $a = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
    condition:
        $a at pe.entry_point

}