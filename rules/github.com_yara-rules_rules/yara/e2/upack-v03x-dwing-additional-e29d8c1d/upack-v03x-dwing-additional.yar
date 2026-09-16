import "pe"
rule Upack_V03X_Dwing_additional: PEiD
{
    strings:
        $a = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E }
    condition:
        $a at pe.entry_point

}