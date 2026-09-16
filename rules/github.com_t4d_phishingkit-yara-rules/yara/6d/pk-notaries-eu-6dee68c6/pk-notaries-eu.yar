rule PK_Notaries_EU : Notaries
{
    meta:
        description = "Phishing Kit impersonating Notaires/Notaries From EU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-05"
        comment = "Phishing Kit - Notaires"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"
        $spec_dir2 = "images"
                $spec_file = "check_logos.php"
        $spec_file2 = "connexion.php"
        $spec_file3 = "lt-inbox.png"
        $spec_file4 = "notaires-belgique.png"
        $spec_file5 = "notaires-lituanie.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}