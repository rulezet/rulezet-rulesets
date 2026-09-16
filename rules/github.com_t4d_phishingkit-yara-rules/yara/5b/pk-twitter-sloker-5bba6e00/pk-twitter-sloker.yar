rule PK_Twitter_sloker : Twitter
{
    meta:
        description = "Phishing Kit impersonating Twitter"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - Twitter - 'BY CODER SLOKER'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "sloker"
                $spec_file = "confirmed.php"
        $spec_file2 = "username.php"
        $spec_file3 = "tg.php"
        $spec_file4 = "twigif1.gif"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}