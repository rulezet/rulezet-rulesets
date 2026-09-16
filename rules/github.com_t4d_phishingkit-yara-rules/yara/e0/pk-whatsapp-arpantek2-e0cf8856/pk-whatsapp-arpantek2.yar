rule PK_Whatsapp_arpantek2 : Whatsapp
{
    meta:
        description = "Phishing Kit impersonating Whatsapp"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-10"
        comment = "Phishing Kit - Whatsapp - 'ARPANTEK'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "cgi-bin"
                $spec_file = "joining.php"
        $spec_file2 = "email.php"
        $spec_file3 = "fb_style.css"
        $spec_file4 = "setting.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}