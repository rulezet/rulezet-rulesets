rule PK_RoyalMail_N1xon : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-12"
        comment = "Phishing Kit - RoyalMail - 'N1xon'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Play"
        $spec_dir2 = "Vu"
                $spec_file = "fethi.php"
        $spec_file2 = "antiip.php"
        $spec_file3 = "cw.php"
        $spec_file4 = "Play_2000.php"
        $spec_file5 = "unlock.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}