import "pe"
rule PEiD_00810_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0__
{
    meta:
        description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)]"
        ep_only = "true"
    strings:
        $a = {EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00}
    condition:
        $a at pe.entry_point
}