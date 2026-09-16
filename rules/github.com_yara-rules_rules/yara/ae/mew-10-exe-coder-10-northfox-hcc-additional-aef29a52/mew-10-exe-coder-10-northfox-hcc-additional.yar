import "pe"
rule Mew_10_exe_coder_10_Northfox_HCC_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }
    condition:
        $a at pe.entry_point

}