rule PK_Netflix_underground : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-31"
        comment = "Phishing Kit - Netflix - 'SPAMMED BY Underground'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Netflix_files"
        $spec_dir2 = "img"
                $spec_file = "yes.php"
        $spec_file2 = "card.php"
        $spec_file3 = "successfully.php"
        $spec_file4 = "FB-f-Logo__blue_57.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}