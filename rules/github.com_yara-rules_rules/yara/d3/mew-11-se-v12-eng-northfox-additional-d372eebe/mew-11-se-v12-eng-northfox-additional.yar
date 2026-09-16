import "pe"
rule Mew_11_SE_v12_Eng_Northfox_additional: PEiD
{
    strings:
        $a = { 06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D }
    condition:
        $a at pe.entry_point

}