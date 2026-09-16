rule PK_BanquePostale_bpos : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-16"
        comment = "Phishing kit - Banque Postale - '━【BPOS】━'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "server"
        $spec_dir1 = "steps"
                $spec_file = "caruit.php"
        $spec_file2 = "badlogurye.php"
        $spec_file3 = "go.php"
        $spec_file4 = "espace.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}