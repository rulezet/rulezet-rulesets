rule PK_SwissPass_zoro : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-10"
        comment = "Phishing Kit - SwissPass - '- ZORO -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "primefaces"
        $spec_dir2 = "languages"
                $spec_file = "a.php"
        $spec_file2 = "realise.php"
        $spec_file3 = "swisspass.min-20200819.js"
        $spec_file4 = "resolved.txt"
        $spec_file5 = "logo_text_de-20200819.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}