rule PK_O365_sengo : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-10"
        comment = "Phishing Kit - O365 - '$_POST[sendgo]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "dp.png"
        $spec_file2 = "index.php"
        $spec_file3 = "newbakground.jpg"
        $spec_file4 = "of.png"
        $spec_file5 = "wo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_file*)
}