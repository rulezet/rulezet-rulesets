rule PK_Netflix_ard8no : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2020-12-06"
        comment = "Phishing Kit - Netflix - 'Ard8no'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "system"
        $spec_dir2 = "panel"
                $spec_file = "confirm.php"
        $spec_file2 = "otp2.php"
        $spec_file3 = "api.php"
        $spec_file4 = "csc_not_amx.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}