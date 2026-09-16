rule PK_SocieteGenerale_rio : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-10"
        comment = "Phishing Kit - Societe Generale - built to steal bank and RIO data"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "panel"
        $spec_dir1 = "graveyard"
        $spec_dir2 = "cdns"
        $spec_file1 = "newips.php"
        $spec_file2 = "get_statu.php"
        $spec_file3 = "inst2.php"
        $spec_file4 = "logo-sg-seul.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}