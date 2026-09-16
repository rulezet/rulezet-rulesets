rule PEiD_00705_FASM_1_5x_
{
    meta:
        description = "[FASM 1.5x]"
        ep_only = "false"
    strings:
        $a = {6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00}
    condition:
        $a
}