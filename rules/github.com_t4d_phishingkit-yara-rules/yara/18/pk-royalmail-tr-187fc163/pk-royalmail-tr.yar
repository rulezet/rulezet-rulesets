rule PK_RoyalMail_tr : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-06"
        comment = "Phishing Kit - RoyalMail - contain turkish comments"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "package.php"
        $spec_file2 = "continue.php"
        $spec_file3 = "997614747.html"
        $spec_file4 = "hcaptcha.html"
        $spec_file5 = "SafeSpace-logo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}