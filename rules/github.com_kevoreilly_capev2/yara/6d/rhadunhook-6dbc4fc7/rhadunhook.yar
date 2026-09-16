rule RhadUnhook
{
    meta:
        cape_options = "bp0=$scan*,action0=scan:rbx,count=0,patch=$target+21:9090"
        packed = "dd4af0f1888977f6d9eb820b19f4afc2a73d1c494a132ab4261498328005dda7"
    strings:
        $scan = {48 85 DB 0F 84 E1 00 00 00 4C 8D 44 24 70 48 8D 54 24 40 48 8B CE 44 89 7C 24 50 4C 89 64 24 40 48 C7 44 24 48 00 00 00 00 C6 44 24 54 00 FF}
        $target = {4D 85 C9 48 8B C6 4A 8D 0C 1E 74 15 48 2B D8 49 2B DB 8A 04 0B 88 01 48 83 C1 01 49 83 E9 01 75 F1 5F 5E 5D 5B C3}
    condition:
        any of them
}