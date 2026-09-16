rule PK_Netflix_mr0x : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-28"
        comment = "Phishing Kit - Netflix - '- MR-0X -' based on a Canada Post phishing kit"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "inc"
        $spec_dir1 = "otp"
                $spec_file = "teleg.php"
        $spec_file2 = "request1.php"
        $spec_file3 = "sms4.php"
        $spec_file4 = "loadingtootp.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                 all of ($spec_file*)
}