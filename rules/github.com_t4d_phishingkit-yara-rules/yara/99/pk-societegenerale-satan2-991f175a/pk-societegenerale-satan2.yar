rule PK_SocieteGenerale_satan2 : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-03"
        comment = "Phishing Kit - Societe Generale - '@author : SATAN2-SCAM'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"
        $spec_dir1 = "main"
        $spec_dir2 = "pages"
        $spec_file1 = "mobile.php"
        $spec_file2 = "sms.php"
        $spec_file3 = "tc_SocieteGenerale_22.js"
        $spec_file4 = "SGAvenirStrokedConseiller24.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}