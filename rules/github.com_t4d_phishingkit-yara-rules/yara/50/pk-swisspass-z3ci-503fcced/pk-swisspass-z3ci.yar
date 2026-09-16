rule PK_SwissPass_z3ci : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-31"
        comment = "Phishing Kit - SwissPass - '- Z3CI -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "CHFINALE"
        $spec_dir2 = "f3636"
                $spec_file = "configuration.php"
        $spec_file2 = "load2.html"
        $spec_file3 = "swisspass.min-20200819.js.download"
        $spec_file4 = "mcidcheck-visasecure.png"
        $spec_file5 = "send4.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}