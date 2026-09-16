rule PK_AustraliaPost_jex404 : AustraliaPost
{
    meta:
        description = "Phishing Kit impersonating Australia Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-08"
        comment = "Phishing Kit - AustraliaPost - instruction file by JeX404"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "sourceApp"
        $spec_dir2 = "htdocs"
                $spec_file = "demande.php"
        $spec_file2 = "funciones.php"
        $spec_file3 = "PosTinTo.php"
        $spec_file4 = "config.inc.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
        all of ($spec_dir*)
}