rule PK_O365_Spin : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-27"
        comment = "Phishing Kit - O365"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "do"
                $spec_file = "spln.php"
        $spec_file2 = "spin.php"
        $spec_file3 = "pai.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and 
        $spec_file3
}