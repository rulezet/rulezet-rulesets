rule PK_Boursorama_jen : Boursorama
{
    meta:
        description = "Phishing Kit impersonating Boursorama"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-26"
        comment = "Phishing kit - Boursorama - using a 'jen' named dir."

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "connexion"
        $spec_dir1 = "logs"
                $spec_file = "boursorama-banque-logo@2x.png"
        $spec_file2 = "carte.php"
        $spec_file3 = "go1.php"
        $spec_file4 = "netcraft_check.php"
        $spec_file5 = "authentification.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}