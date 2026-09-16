rule PK_BanquePostale_m3tri : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-17"
        comment = "Phishing kit - Banque Postale - 'Postale log By METRI'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "postale-M3tri_files"
        $spec_dir1 = "M3tri-hash-bots"
                $spec_file = "anti9.php"
        $spec_file2 = "authentification_forte_non_adherents.html"
        $spec_file3 = "logo-la-banque-postale.png"
        $spec_file4 = "plate.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}