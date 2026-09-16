rule PK_AustraliaPost_yass : AustraliaPost
{
    meta:
        description = "Phishing Kit impersonating Australia Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-08"
        comment = "Phishing Kit - AustraliaPost - 'By Yass ht'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "send"
        $spec_dir2 = "sms"
                $spec_file = "card.php"
        $spec_file2 = "sms2.html"
        $spec_file3 = "sms2.php"
        $spec_file4 = "sms1.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
        all of ($spec_dir*)
}