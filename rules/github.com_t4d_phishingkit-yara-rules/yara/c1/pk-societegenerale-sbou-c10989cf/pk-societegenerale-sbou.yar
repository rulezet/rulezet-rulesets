rule PK_SocieteGenerale_sbou : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-02"
        comment = "Phishing Kit - Societe Generale - 'powered by bikola'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "AntiBoot"
        $spec_file1 = "logo-sg-seul.svg"
        $spec_file2 = "filter.php"
        $spec_file3 = "load1.html"
        $spec_file4 = "pass.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}