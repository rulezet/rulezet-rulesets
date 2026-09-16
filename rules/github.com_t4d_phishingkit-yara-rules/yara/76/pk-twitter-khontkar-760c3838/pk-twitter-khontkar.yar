rule PK_Twitter_Khontkar : Twitter
{
    meta:
        description = "Phishing Kit impersonating Twitter"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-17"
        comment = "Phishing Kit - Twitter - reference to Khontkar lyrics (a Turkish rapper)"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "img"
                $spec_file = "banane.php"
        $spec_file2 = "banane1.php"
        $spec_file3 = "yavru.php"
        $spec_file4 = "twitter.png"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}