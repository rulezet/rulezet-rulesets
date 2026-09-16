rule PK_MondialRelay_traffyque : MondialRelay
{
    meta:
        description = "Phishing Kit impersonating Mondial Relay"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-29"
        comment = "Phishing Kit - MondialRelay - 'Traffyque'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "panel"
        $spec_dir2 = "actions"
        $spec_dir3 = "enc"

                $spec_file = "error.php"
        $spec_file2 = "billing-info.php"
        $spec_file3 = "loading-visa-verification.php"
        $spec_file4 = "3d secure visa.php"
        $spec_file5 = "colis.png"
        $spec_file6 = "thegreenweb-mondialrelayfr.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}