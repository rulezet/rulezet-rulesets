import "pe"
rule PEiD_03512_Xtreme_Protector_v1_05_
{
    meta:
        description = "[Xtreme-Protector v1.05]"
        ep_only = "true"
    strings:
        $a = {E9 ?? ?? 00 00 00 00 00 00 00 00}
    condition:
        $a at pe.entry_point
}