rule PK_USBank_otp : USBank
{
    meta:
        description = "Phishing Kit impersonating U.S. Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-12"
        comment = "Phishing Kit - USBank"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"
        $spec_dir2 = "bootstrap"
                $spec_file = "email.php"
        $spec_file2 = "phone.html"
        $spec_file3 = "empass.html"
        $spec_file4 = "telegram.php"
        $spec_file5 = "lg.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}