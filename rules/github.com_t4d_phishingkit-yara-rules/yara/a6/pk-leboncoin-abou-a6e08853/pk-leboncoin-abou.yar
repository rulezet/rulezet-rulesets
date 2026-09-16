rule PK_LeBonCoin_abou : LeBonCoin
{
    meta:
        description = "Phishing Kit impersonating Le Bon Coin"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-25"
        comment = "Phishing Kit - LeBonCoin - 'saved from url=(0071)file:///C:/Users/jam/Desktop/abou-boncoin/leboncoin%20-%20connexion.htm'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Confirmez-votre-adresse_fichiers"
        $spec_dir2 = "Félicitation_fichiers"
                $spec_file = "Confirmez-votre-adresse.htm"
        $spec_file2 = "leboncoin-connexion.html"
        $spec_file3 = "hh.png"
        $spec_file4 = "lbc-front-web-logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}