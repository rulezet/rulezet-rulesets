rule Cloaked_as_JPG {
        meta:
                description = "Detects a cloaked file as JPG"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
                score = 70
        strings:
                $ext = "extension: .jpg"
        condition:
                $ext and uint16be(0x00) != 0xFFD8
}