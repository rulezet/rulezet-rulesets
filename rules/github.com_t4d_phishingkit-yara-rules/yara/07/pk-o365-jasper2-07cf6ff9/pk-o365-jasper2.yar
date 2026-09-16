rule PK_O365_jasper2 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1432227436834562049"
        date = "2021-12-08"
        comment = "Phishing Kit - O365 - 'Created By JaSpEr'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "Encrypted.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "sso.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}