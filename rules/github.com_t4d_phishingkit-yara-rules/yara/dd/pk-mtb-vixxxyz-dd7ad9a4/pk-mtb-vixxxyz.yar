rule PK_MTB_VixxxyZ : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1538112955505573888"
        date = "2022-06-18"
        comment = "Phishing Kit - M&T Bank - 'This is M&T   Bank Scama By @VixxxyZ On tg'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "VixxxyZ"
        $spec_dir2 = "login"
                $spec_file = "vixxxYZ.php"
        $spec_file2 = "vixxxyz5.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "validated.php"
        $spec_file5 = "email_identity.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*) 
}