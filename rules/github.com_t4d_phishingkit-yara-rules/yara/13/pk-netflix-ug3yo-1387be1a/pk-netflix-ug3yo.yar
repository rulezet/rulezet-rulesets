rule PK_Netflix_ug3yo : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-25"
        comment = "Phishing Kit - Netflix - 'UG3YO SP NETFLIX LOGIN'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "workshop"
        $spec_dir2 = "app"
                $spec_file = "step4.php"
        $spec_file2 = "mine.php"
        $spec_file3 = "none2.css"
        $spec_file4 = "nf-icon-v1-93.ttf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}