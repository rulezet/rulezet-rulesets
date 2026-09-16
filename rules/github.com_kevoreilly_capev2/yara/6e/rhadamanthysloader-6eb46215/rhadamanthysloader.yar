rule RhadamanthysLoader
{
    meta:
        author = "kevoreilly"
        description = "Rhadamanthys Loader"
        cape_type = "Rhadamanthys Loader"
    strings:
        $ref = {33 D2 B9 0B 00 00 00 F7 F1 B8 01 00 00 00 6B C8 00 8D 84 0D [4] 0F BE 0C 10 8B 95 [4] 03 95 [4] 0F B6 02 33 C1 8B 8D [4] 03 8D [4] 88 01}
        $ntdll = {B9 6E 00 00 00 66 89 8D [4] BA 74 00 00 00 66 89 95 [4] B8 64 00 00 00 66 89 85 [4] B9 6C 00 00 00 66 89 8D [4] BA 6C 00 00 00 66 89 95}
        $exit = {6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8B 95 [4] 52 8B 85 [4] 50 6A 00 68 FF FF 1F 00}
    condition:
        2 of them
}