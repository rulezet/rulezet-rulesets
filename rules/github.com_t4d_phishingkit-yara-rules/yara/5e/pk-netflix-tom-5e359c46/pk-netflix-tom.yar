rule PK_Netflix_tom : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-06"
        comment = "Phishing Kit - Netflix - 'Till Tom Results'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "translate"
        $spec_dir2 = "eradox"
                $spec_file = "zeus.php"
        $spec_file2 = "lg.php"
        $spec_file3 = "billing.php"
        $spec_file4 = "NetflixSans_W_Th.woff"
        $spec_file5 = "nficon2023.ico"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}