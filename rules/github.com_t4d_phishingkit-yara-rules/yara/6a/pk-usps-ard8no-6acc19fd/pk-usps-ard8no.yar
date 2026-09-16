rule PK_USPS_ard8no : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-08"
        comment = "Phishing Kit - USPS - 'ard8no das'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "verification"
        $spec_dir2 = "rez"
                $spec_file = "payment.php"
        $spec_file2 = "sms2.php"
        $spec_file3 = "wait.php"
        $spec_file4 = "send4.php"
        $spec_file5 = "schedule-redelivery.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}