rule PK_BanquePostale_money : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing kit - Banque Postale - 'From: <noreply@money.cj>'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "config"
        $spec_dir1 = "data"
                $spec_file = "trans.php"
        $spec_file2 = "funcs.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "cle-digitale.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}