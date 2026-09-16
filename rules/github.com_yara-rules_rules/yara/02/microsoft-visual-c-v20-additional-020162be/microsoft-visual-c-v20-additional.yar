import "pe"
rule Microsoft_Visual_C_v20_additional: PEiD
{
    strings:
        $a = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }
    condition:
        $a at pe.entry_point

}