rule PK_Snapchat_tgreat : Snapchat
{
    meta:
        description = "Phishing Kit impersonating Snapchat"
        licence = "1GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-26"
        comment = "Phishing Kit - Snapchat - 'Telegram ID: @tgreat_coder Snap Chat'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "myeyes.php"
        $spec_file2 = "reg5.php"
        $spec_file3 = "number.html"
        $spec_file4 = "snapchat-app-icon.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}