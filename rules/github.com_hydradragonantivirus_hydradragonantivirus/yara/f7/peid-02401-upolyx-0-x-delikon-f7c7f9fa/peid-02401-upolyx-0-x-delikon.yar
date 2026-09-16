rule PEiD_02401_UPolyX_0_x____Delikon_
{
    meta:
        description = "[UPolyX 0.x -> Delikon]"
        ep_only = "true"
    strings:
        $a = {81 FD 00 FB FF FF 83 D1 ?? 8D 14 2F 83 FD FC 76 ?? 8A 02 42 88 07 47 49 75}
    condition:
        $a
}