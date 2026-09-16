rule PK_BanquePostale_sicilien : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing kit - Banque Postale - 'Postal Sicilien Le Pétrolier'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "asset"
        $spec_dir1 = "uploads"
                $spec_file = "justificatif.html"
        $spec_file2 = "inscrir_email_ici.php"
        $spec_file3 = "mise_a_jour_Certicode.php"
        $spec_file4 = "response.php"
        $spec_file5 = "certicode.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}