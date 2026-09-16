rule PK_Mellat_milad : Mellat
{
    meta:
        description = "Phishing Kit impersonating Mellat Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-03"
        comment = "Phishing Kit - Mellat Bank - 'PHP Encoding by MiladWorkShop PHP Encoder'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "otpcode"
        $spec_dir2 = "msg"
        $spec_dir3 = "woff2"
                $spec_file = "payment.minabc.js"
        $spec_file2 = "tel-otp.php"
        $spec_file3 = "esprit_fa.minabc.css"
        $spec_file4 = "mellat_arc_footer.svg"
        $spec_file5 = "IRANSansWeb_UltraLightd41d.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*) 
}