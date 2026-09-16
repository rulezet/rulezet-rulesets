rule PK_RoyalCU_g1ng : RoyalCU
{
    meta:
        description = "Phishing Kit impersonating Royal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-25"
        comment = "Phishing Kit - RoyalCU - '[+] G 1 N G  [+]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Royal_files"
        $spec_dir2 = "otp_files"
                $spec_file = "load2.php"
        $spec_file2 = "sms-error.php"
        $spec_file3 = "3p_cookie_test.html"
        $spec_file4 = "01516-logo-lg-md-publish.png"
    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}