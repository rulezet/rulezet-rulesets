rule PK_Postbank_ded : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-09"
        comment = "Phishing Kit - Postbank"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mobile_tan_files"
        $spec_dir1 = "tan_files"
        $spec_dir2 = "Loginloading_files"
                $spec_file = "tan.html"
        $spec_file2 = "mobile_tan.html"
        $spec_file3 = "deded.php"
        $spec_file4 = "0om4.php"
        $spec_file5 = "account.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}