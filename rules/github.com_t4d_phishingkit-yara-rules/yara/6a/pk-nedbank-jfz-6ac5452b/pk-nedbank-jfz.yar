rule PK_Nedbank_jfz : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-27"
        comment = "Phishing Kit - Nedbank - '- by JFZ'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "media"
        $spec_dir2 = "logs"
                $spec_file = "configure.php"
        $spec_file2 = "NedbankIcon.svg"
        $spec_file3 = "status_1.php"
        $spec_file4 = "visitor_log.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}