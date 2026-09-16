rule PEiD_03419_VX__Tibs_Zhelatin__StormWorm__variant_
{
    meta:
        description = "[VX: Tibs/Zhelatin \"StormWorm\" variant]"
        ep_only = "true"
    strings:
        $a = {FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8}
    condition:
        $a
}