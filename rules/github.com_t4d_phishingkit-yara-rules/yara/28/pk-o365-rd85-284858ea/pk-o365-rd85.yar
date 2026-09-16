rule PK_O365_rd85 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-01"
        comment = "Phishing Kit - O365 - 'xLs' RD85"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
                $spec_file = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "success.PNG"
        $spec_file4 = "microsoft_logo.svg"
        $spec_file5 = "key.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
        $spec_dir and 
                all of ($spec_file*)
}