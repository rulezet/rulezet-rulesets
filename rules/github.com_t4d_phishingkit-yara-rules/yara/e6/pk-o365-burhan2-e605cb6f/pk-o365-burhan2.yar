rule PK_O365_Burhan2 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-06"
        comment = "Phishing Kit - O365 - 'BURHAN FUDPAGES [.] RU'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "css"
                $spec_file = "node2.php"
        $spec_file2 = "incorrectagain.php"
        $spec_file3 = "next3.php"
        $spec_file4 = "thankyou.php"
        $spec_file5 = "csscheckbox_a4824bcf5d413f078bdd6abd3e6e5bf4.png"
        $spec_file6 = "rent.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}