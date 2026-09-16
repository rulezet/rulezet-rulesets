rule PK_SingaporePost_yass : SingaporePost
{
    meta:
        description = "Phishing Kit impersonating SingaporePost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - Singapore Post - 'By Yass ht'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "manage"
        $spec_dir2 = "BANKIA_files"
                $spec_file = "proxyblock.php"
        $spec_file2 = "block3.php"
        $spec_file3 = "sms2.html"
        $spec_file4 = "card.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}