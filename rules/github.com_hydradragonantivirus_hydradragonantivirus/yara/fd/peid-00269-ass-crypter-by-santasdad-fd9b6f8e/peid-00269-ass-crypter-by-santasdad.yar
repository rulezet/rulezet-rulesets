rule PEiD_00269_ass___crypter____by_santasdad_
{
    meta:
        description = "[ass - crypter -> by santasdad]"
        ep_only = "true"
    strings:
        $a = {55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B}
    condition:
        $a
}