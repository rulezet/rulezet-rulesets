rule PK_RoyalMail_rootdr : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-26"
        comment = "Phishing Kit - RoyalMail - 'BLACKFORCE REZDATA' 'Coded By Root_Dr'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "prevents"
        $spec_dir2 = "botActVbv"
                $spec_file = "payment.php"
        $spec_file2 = "infoz.php"
        $spec_file3 = "panel.php"
        $spec_file4 = "css_2kSODmeFaX7ybMB6AeohAt_hNxiz95dKI0JJ2-F4f_k.css"
        $spec_file5 = "blackforce.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}