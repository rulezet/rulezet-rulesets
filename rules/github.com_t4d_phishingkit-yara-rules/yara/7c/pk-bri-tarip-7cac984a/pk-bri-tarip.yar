rule PK_BRI_tarip : BRI
{
    meta:
        description = "Phishing Kit impersonating Bank Rakyat Indonesia (BRI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - BRI - 'BRI TARIP'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "req"
        $spec_dir2 = "img"
                $spec_file = "saldo.php"
        $spec_file2 = "no.php"
        $spec_file3 = "4.js"
        $spec_file4 = "vibr.js"
        $spec_file5 = "1703668668502.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}