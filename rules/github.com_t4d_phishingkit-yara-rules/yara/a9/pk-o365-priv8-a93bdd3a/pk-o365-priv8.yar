rule PK_O365_Priv8 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-20"
        comment = "Phishing Kit - O365"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Priv8"
                $spec_file = ".rst.htm11"
        $spec_file2 = "ind.php"
        $spec_file3 = "n.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}