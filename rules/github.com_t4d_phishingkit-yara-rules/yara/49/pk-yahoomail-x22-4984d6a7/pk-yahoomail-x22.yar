rule PK_YahooMail_x22 : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-26"
        comment = "Phishing Kit - Yahoo Mail - 'x2.php file'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
                $spec_file = "x2.php"
        $spec_file2 = "home.shtml"
        $spec_file3 = "cont.php"
        $spec_file4 = "i-wechat.jpg"
        $spec_file5 = "date.pdf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}