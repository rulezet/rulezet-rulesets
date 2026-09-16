import "pe"
rule Microsoft_Visual_C_v20: PEiD
{
    strings:
        $a = { 55 8B EC 56 57 BF 8B 3B F7 }
        $b = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}