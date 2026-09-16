rule PK_TaiwanPost_alfabrabus : TaiwanPost
{
    meta:
        description = "Phishing Kit impersonating Taiwan POST"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-22"
        comment = "Phishing Kit - Taiwan POST - 'By @ALFABRABUS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "eradox"
        $spec_dir2 = "php"
        $spec_dir3 = "js"
                $spec_file = "send6.php"
        $spec_file2 = "serveur.php"
        $spec_file3 = "cart.php"
        $spec_file4 = "sms4.php"
        $spec_file5 = "PK_TaiwanPost_alfabrabus"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}