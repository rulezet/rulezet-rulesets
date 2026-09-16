rule PK_AdobePDF_hse : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-25"
        comment = "Phishing Kit - Adobe PDF Online - 'Hades Silent Exploits'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "adobe"
                $spec_file = "index.php"
        $spec_file2 = "login.php"
        $spec_file3 = "logg.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}