rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence"
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"

                $parallels_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        all of them
}