rule PK_Etisalat_myboss : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-25"
        comment = "Phishing Kit - Etisalat - 'Cc: myboss@example.com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "PaymentEx"
        $spec_dir2 = "3ds"
        $spec_dir3 = "fonts"
                $spec_file = "handler.php"
        $spec_file2 = "payment.php"
        $spec_file3 = "start_transaction.php"
        $spec_file4 = "cookie.js"
        $spec_file5 = "eWFiYWx0b2dvcm90.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}