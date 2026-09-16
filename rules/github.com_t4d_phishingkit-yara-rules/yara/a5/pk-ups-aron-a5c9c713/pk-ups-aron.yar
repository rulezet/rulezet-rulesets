rule PK_UPS_aron : UPS
{
    meta:
        description = "Phishing Kit impersonating UPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-30"
        comment = "Phishing Kit - UPS - '=[ UPS ARON-TN ]='"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "VBV_files"
                $spec_file = "settings.php"
        $spec_file2 = "xx.png"
        $spec_file3 = "thankyou.php"
        $spec_file4 = "Charles.php"
        $spec_file5 = "behi.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}