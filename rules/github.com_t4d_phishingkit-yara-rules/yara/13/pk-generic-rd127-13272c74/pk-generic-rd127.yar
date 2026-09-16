rule PK_Generic_RD127 : RD127_Generic
{
    meta:
        description = "Phishing Kit - RD127 - Generic email credentials stealer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-03"
        comment = "Phishing Kit - RD127"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "css"
                $spec_file = "weblogo.png"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "index.html"
        $spec_file5 = "landing.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}