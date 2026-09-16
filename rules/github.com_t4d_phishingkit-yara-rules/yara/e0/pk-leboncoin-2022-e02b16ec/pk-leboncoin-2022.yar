rule PK_LeBonCoin_2022 : LeBonCoin
{
    meta:
        description = "Phishing Kit impersonating Le Bon Coin"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-10-25"
        comment = "Phishing Kit - LeBonCoin - 'Mirrored from ... Tue, 16 Feb 2022 23:04:58 GMT'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"
                $spec_file = "info-bancaire.php"
        $spec_file2 = "virement.php"
        $spec_file3 = "access-mail.php"
        $spec_file4 = "page.c9a650b6b85d7c2bdddc.css"
        $spec_file5 = "lbclogo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}