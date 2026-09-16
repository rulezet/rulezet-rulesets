rule PK_DeutschePost_zabi : DeutschePost
{
    meta:
        description = "Phishing Kit impersonating DeutschePost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-12"
        comment = "Phishing Kit - DeutschePost - '. $zabi .'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "manage"
                $spec_file = "card.php"
        $spec_file2 = "block3.php"
        $spec_file3 = "1.css"
        $spec_file4 = "proxyblock.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}