rule STXRatLoader
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/stx-rat-a-new-rat-in-2026-with-infostealer-capabilities"
        cape_type = "STXRat Loader"
    strings: 
        
                $ror1 = { B9 4E 15 F5 1F E8 }
                $ror2 = {
            BA 35 EC 33 57
            48 8B C8
            48 8B D8
            E8
        }
                $ror3 = {
            BA 36 91 AC 32
        }
                $ror4 = {
            BA 7E 91 90 5A
            48 8B C8
            E8
        }
                $s1 = {
            69 D0 47 86 C8 61
        }
                $s2 = {
            B8 85 10 42 08
            41 F7 E2
        }
                $s3 = {
            41 C1 C8 0E
            0F BE C0
            44 03 C0
        }
        $init = "init"
        $run = "run"
    condition: 
        uint16(0) == 0x5a4d and $init and $run and 1 of ($ror*) and 1 of ($s*)
}