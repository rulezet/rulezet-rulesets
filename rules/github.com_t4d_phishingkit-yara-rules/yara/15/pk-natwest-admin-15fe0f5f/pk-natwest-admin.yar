rule PK_NatWest_admin : NatWest
{
    meta:
        description = "Phishing Kit impersonating NatWest bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-28"
        comment = "Phishing Kit - NatWest - 'From: admin@admin.com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "security_files"
        $spec_dir2 = "login_files"
        $spec_dir3 = "includes"
                $spec_file = "security_retry.php"
        $spec_file2 = "complete.php"
        $spec_file3 = "my_email.php"
        $spec_file4 = "loginWithCardPAN.js"
        $spec_file5 = "li5_outer_frame_top_curve.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}