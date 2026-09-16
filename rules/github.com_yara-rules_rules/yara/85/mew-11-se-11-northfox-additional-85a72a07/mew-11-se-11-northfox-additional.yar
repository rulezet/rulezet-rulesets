import "pe"
rule MEW_11_SE_11_Northfox_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00 }
    condition:
        $a at pe.entry_point

}