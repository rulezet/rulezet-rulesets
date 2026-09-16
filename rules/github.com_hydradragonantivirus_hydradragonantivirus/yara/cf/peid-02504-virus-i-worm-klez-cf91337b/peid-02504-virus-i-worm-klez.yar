rule PEiD_02504_VIRUS___I_Worm_KLEZ_
{
    meta:
        description = "[VIRUS - I-Worm.KLEZ]"
        ep_only = "false"
    strings:
        $a = {55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0}
    condition:
        $a
}