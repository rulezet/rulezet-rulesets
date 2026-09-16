rule PK_Netflix_access : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-07-12"
        comment = "Phishing Kit - Netflix - 'using access* varibales'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "page_settings"
        $spec_dir2 = "system"
        $spec_dir3 = "languages"
                $spec_file = "step5.php"
        $spec_file2 = "otp3.php"
        $spec_file3 = "kko.php"
        $spec_file4 = "jquery.ccvalid.js"
        $spec_file5= "nt_logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}