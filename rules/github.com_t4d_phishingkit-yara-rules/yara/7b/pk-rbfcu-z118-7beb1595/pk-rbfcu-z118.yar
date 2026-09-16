rule PK_RBFCU_z118 : RBFCU
{
    meta:
        description = "Phishing Kit impersonating Randolph-Brooks Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-10-07"
        comment = "Phishing Kit - RBFCU - '$Z118_EMAIL'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "functions"
        $spec_dir1 = "grabber"
                $spec_file = "config.php"
        $spec_file2 = "rbfcu-logo.svg"
        $spec_file3 = "session_login.php"
        $spec_file4 = "Thankyou.php"
        $spec_file5 = "CARD.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}