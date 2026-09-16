rule PK_SocieteGenerale_Galvo : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-31"
        comment = "Phishing Kit - Societe Generale - by 'Galvo'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mobi"
        $spec_file1 = "redpu.html"
        $spec_file2 = "error3.php"
        $spec_file3 = "feed5.php"
        $spec_file4 = "valop.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}