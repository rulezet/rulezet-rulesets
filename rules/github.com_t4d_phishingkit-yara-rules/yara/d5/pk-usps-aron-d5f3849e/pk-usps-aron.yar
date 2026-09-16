rule PK_USPS_aron : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-01"
        comment = "Phishing Kit - USPS - 'CODED BY ARON-TN'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "anti"
                $spec_file = "id.php"
        $spec_file2 = "index5.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "usps.png"
        $spec_file5 = "mailto.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}