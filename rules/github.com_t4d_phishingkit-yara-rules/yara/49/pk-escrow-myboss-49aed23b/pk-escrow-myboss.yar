rule PK_Escrow_myboss : Escrow
{
    meta:
        description = "Phishing Kit impersonating Escrow.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-25"
        comment = "Phishing Kit - Escrow - 'Cc: myboss@example.com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "php"
        $spec_dir2 = "img"
        $spec_dir3 = "user"
                $spec_file = "process.php"
        $spec_file2 = "signup.php"
        $spec_file3 = "start_transaction.php"
        $spec_file4 = "mile.jpg"
        $spec_file5 = "reg.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}