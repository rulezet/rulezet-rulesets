import "pe"
rule PEiD_01628_PEQuake_V0_06____forgat_
{
    meta:
        description = "[PEQuake V0.06 -> forgat]"
        ep_only = "true"
    strings:
        $a = {E8 A5 00 00 00}
    condition:
        $a at pe.entry_point
}