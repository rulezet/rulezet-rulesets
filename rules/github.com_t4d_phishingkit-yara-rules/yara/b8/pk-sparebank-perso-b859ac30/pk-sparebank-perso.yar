rule PK_SpareBank_perso : SpareBank
{
    meta:
        description = "Phishing Kit impersonating SpareBank1"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-02-15"
        comment = "Phishing Kit - SpareBank - using 'perso.php' file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "BankID_fichiers"
        $spec_dir2 = "fichier"
                $spec_file = "egan.php"
        $spec_file2 = "a_002.html"
        $spec_file3 = "perso.php"
        $spec_file4 = "SPOL.OL-2ed6562c.png"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}