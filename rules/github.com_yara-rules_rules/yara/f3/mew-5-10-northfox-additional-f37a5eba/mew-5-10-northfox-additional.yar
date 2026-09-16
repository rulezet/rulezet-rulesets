import "pe"
rule MEW_5_10_Northfox_additional: PEiD
{
    strings:
        $a = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }
    condition:
        $a at pe.entry_point

}