rule PK_Avida_zabi : Avida
{
    meta:
        description = "Phishing Kit impersonating Avida Finance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-25"
        comment = "Phishing Kit - Avida - use '$zabi' variable name"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "api"
        $spec_dir2 = "mobil_fichiers"
                $spec_file = "accpt.htm"
        $spec_file2 = "mobil.htm"
        $spec_file3 = "perso.htm"
        $spec_file4 = "step4.php"
        $spec_file5 = "avida-logo.png"
    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}