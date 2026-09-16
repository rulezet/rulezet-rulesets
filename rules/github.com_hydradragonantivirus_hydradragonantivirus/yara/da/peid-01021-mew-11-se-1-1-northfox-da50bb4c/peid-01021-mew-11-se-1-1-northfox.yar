rule PEiD_01021_MEW_11_SE_1_1____Northfox_
{
    meta:
        description = "[MEW 11 SE 1.1 -> Northfox]"
        ep_only = "false"
    strings:
        $a = {E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00}
    condition:
        $a
}