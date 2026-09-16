rule PK_SwissPass_nova : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-15"
        comment = "Phishing Kit - SwissPass - 'From zero by Nova'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "primefaces"
        $spec_dir2 = "process"
                $spec_file = "confirmation_error.php"
        $spec_file2 = "payment_submit.php"
        $spec_file3 = "swisspass.min-20200819.js.download"
        $spec_file4 = "logo_text_de-20200819.svg"
        $spec_file5 = "swisspass.min-20200819.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}