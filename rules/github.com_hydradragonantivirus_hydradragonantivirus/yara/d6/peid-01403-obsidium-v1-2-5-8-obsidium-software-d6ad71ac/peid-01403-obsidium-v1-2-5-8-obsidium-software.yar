rule PEiD_01403_Obsidium_V1_2_5_8____Obsidium_Software_
{
    meta:
        description = "[Obsidium V1.2.5.8 -> Obsidium Software]"
        ep_only = "true"
    strings:
        $a = {EB 01 ?? E8 ?? 00 00 00}
    condition:
        $a
}