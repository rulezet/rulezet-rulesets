rule PK_ATandT_yb : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-14"
        comment = "Phishing Kit - ATandT - 'Created By yb'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "AT&T.html"
        $spec_file2 = "now.php"
        $spec_file3 = "rd25RPk.png"
        $spec_file4 = "UNj1Ij7.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}