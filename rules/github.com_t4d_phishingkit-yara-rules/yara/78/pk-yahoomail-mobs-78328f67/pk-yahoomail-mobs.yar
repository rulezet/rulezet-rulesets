rule PK_YahooMail_Mobs : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-01"
        comment = "Phishing Kit - Yahoo Mail - 'Created By MOBS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "yahoo"
                $spec_file = "logindetails.php"
        $spec_file2 = "yahoo.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_dir
}