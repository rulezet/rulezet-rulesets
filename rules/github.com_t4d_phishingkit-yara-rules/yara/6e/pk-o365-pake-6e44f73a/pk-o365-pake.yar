rule PK_O365_pake : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - O365 - using pake.ico file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "manager"
                $spec_file = "pake.ico"
        $spec_file2 = "geoplugin.class.php"
        $spec_file3 = "ellipsis_white.svg"
        $spec_file4 = "one nation.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}