rule PK_SwissPass_gxp : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-08"
        comment = "Phishing Kit - SwissPass - '-GXP-'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "l3amer"
        $spec_dir2 = "scriptat"
                $spec_file = "kantonalbank.php"
        $spec_file2 = "maghat_lebssouch.js"
        $spec_file3 = "vuxe.php"
        $spec_file4 = "swisscard.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}