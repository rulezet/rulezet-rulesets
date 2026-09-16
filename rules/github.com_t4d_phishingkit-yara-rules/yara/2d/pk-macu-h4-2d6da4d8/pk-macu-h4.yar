rule PK_MACU_H4 : MACU
{
    meta:
        description = "Phishing Kit impersonating Mountain America Credit Union (MACU)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-26"
        comment = "Phishing Kit - Email Verification - 'Emp0w3r3d By Mr.H4'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "MACU"
                $spec_file = "verify.php"
        $spec_file2 = "index.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2
}