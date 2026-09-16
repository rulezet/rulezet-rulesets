rule PK_BanquePostale_z0n51 : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-26"
        comment = "Phishing kit - Banque Postale - 'Author: z0n51'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "php-credit-card-validator"
        $spec_dir1 = "login"
                $spec_file = "submit.php"
        $spec_file2 = "botadmin.php"
        $spec_file3 = "functions.php"
        $spec_file4 = "certicode.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}