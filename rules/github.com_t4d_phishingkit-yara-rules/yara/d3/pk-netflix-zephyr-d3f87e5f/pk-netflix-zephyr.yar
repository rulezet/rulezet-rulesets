rule PK_Netflix_zephyr : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-12-23"
        comment = "Phishing Kit - Netflix - ZephyrScama"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "app"
        $spec_dir2 = "scama"
        $spec_dir3 = "_config"
                $spec_file = "nficon2016.png"
        $spec_file2 = "icon_cartes_bancaires_2x.png"
        $spec_file3 = "vbv.php"
        $spec_file4 = "loginBase.09e271325f8873705389.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}