rule PEiD_01051_Microsoft_Visual_Basic_v5_0___v6_0_
{
    meta:
        description = "[Microsoft Visual Basic v5.0 - v6.0]"
        ep_only = "false"
    strings:
        $a = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00}
    condition:
        $a
}