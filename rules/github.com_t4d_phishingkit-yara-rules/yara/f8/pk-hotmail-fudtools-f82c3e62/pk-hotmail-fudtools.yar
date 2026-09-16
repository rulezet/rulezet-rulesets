rule PK_Hotmail_fudtools : Hotmail
{
    meta:
        description = "Phishing Kit impersonating Hotmail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - Hotmail - 'Created BY fudtools[.]com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "thankyou.html"
        $spec_file2 = "mailer.php"
        $spec_file3 = "outlook_cover_640x360.jpg"
        $spec_file4 = "hosted-exchange-logo.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}