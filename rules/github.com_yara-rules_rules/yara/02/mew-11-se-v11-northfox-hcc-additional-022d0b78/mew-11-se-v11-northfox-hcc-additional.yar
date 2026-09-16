import "pe"
rule MEW_11_SE_v11_Northfox_HCC_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C }
    condition:
        $a at pe.entry_point

}