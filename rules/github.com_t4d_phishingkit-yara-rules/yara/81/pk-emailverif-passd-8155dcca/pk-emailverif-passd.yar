rule PK_EmailVerif_passd : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-20"
        comment = "Phishing Kit - Email Verification"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "login_files"
        $spec_dir2 = "img"
                $spec_file = "login.php"
        $spec_file2 = "logo.png"
        $spec_file3 = "loginBasic.css"
        $spec_file4 = "loginAdvanced.css"
        $spec_file5 = "middle.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}