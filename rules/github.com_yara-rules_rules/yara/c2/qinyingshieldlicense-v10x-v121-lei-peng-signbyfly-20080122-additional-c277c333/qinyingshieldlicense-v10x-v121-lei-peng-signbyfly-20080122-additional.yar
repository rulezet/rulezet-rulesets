import "pe"
rule QinYingShieldLicense_V10X_V121_Lei_Peng_SignByfly_20080122_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 55 8B EC 56 57 53 34 99 47 49 34 33 EF 31 CD F5 B0 CB B5 B0 A3 A1 A3 A1 B9 FE B9 FE B9 FE B9 FE BF C9 CF A7 D1 BD A3 AC C4 E3 B2 BB D6 AA B5 C0 D5 E2 C0 EF B5 C4 D6 B8 C1 EE CA C7 CA B2 C3 B4 A3 A1 B9 FE B9 }
    condition:
        $a at pe.entry_point

}