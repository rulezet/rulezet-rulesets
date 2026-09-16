rule PK_USPS_okbbx : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-12"
        comment = "Phishing Kit - USPS - '$_POST[okbbx]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "inc"
                $spec_file = "index9.php"
        $spec_file2 = "thanks.php"
        $spec_file3 = "functions.php"
        $spec_file4 = "app.php"
        $spec_file5 = "id.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}