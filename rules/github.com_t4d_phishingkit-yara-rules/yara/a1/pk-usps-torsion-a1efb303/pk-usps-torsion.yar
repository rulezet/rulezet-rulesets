rule PK_USPS_torsion : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-08"
        comment = "Phishing Kit - USPS - contain a directory named 'torsion'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "7_files"
        $spec_dir2 = "11"
        $spec_dir3 = "anti"
                $spec_file = "laylay.css"
        $spec_file2 = "end.php"
        $spec_file3 = "shadow8.php"
        $spec_file4 = "config3.php"
        $spec_file5 = "usps_logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}