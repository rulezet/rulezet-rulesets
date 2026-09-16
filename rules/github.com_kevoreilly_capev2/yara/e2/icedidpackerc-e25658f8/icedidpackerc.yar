rule IcedIDPackerC
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "c06805b6efd482c1a671ec60c1469e47772c8937ec0496f74e987276fa9020a5"
        hash = "265c1857ac7c20432f36e3967511f1be0b84b1c52e4867889e367c0b5828a844"
    strings:
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 3A ED 74}
        $alloc = {41 B8 00 10 00 00 8B D0 33 C9 66 3B ?? (74|0F 84)}
    condition:
        uint16(0) == 0x5A4D and all of them
}