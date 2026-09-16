rule PK_Gmail_westgirl : GMail
{
    meta:
        description = "Phishing Kit - impersonating GMail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-10-04"
        comment = "Phishing Kit - GMail - 'Created By WeStGiRl'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_file = "verification.php"
        $spec_file2 = "info2.php"
        $spec_file3 = "signin.php"
        $spec_file4 = "sign.png"
        $spec_file5 = "prof2.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}