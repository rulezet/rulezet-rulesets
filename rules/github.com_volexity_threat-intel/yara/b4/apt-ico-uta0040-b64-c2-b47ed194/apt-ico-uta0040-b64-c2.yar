rule apt_ico_uta0040_b64_c2 : UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of malicious ICO files used in 3CX compromise."
        date = "2023-03-30"
        hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $IEND_dollar = {49 45 4e 44 ae 42 60 82 24}         $IEND_nodollar = {49 45 4e 44 ae 42 60 82 } 
    condition:
        uint16be(0) == 0x0000 and
        filesize < 120KB and
        (
            $IEND_dollar in (filesize-500..filesize) and not
            $IEND_nodollar in (filesize-20..filesize) and
            for any k in (1..#IEND_dollar):
                (
                for all i in (1..4):
                    (
                                                uint8(@IEND_dollar[k]+!IEND_dollar[k] + i ) < 123 and
                        uint8(@IEND_dollar[k]+!IEND_dollar[k] + i) > 47
                    )
                )
        )
}