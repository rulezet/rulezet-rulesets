rule PK_YahooMail_boteye : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.youtube.com/channel/UCCVuxW0Ouftl1i7LGALW_4g"
        date = "2021-05-05"
        comment = "Phishing Kit - Yahoo Mail - 'From: BOTeye v1.5'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "challenged_files"
                $spec_file = "cast.php"
        $spec_file2 = "proxy.php"
        $spec_file3 = "rapid-3.js"
        $spec_file4 = "proxy.ini"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}