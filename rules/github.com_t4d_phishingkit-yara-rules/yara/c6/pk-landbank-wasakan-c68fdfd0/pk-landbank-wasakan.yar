rule PK_Landbank_wasakan : Landbank
{
    meta:
        description = "Phishing Kit impersonating Landbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-12"
        comment = "Phishing Kit - Landbank - 'From: $host$path Landbank Wasakan'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "landbank_files"
        $spec_dir2 = "otp-system"
                $spec_file = "info-process.php"
        $spec_file2 = "otp-access3.php"
        $spec_file3 = "process-login.php"
        $spec_file4 = "mobile-num.php"
        $spec_file5 = "landbankrez.zd"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}