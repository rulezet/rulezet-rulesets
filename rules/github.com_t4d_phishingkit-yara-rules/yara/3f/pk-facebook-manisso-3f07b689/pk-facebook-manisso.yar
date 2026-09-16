rule PK_Facebook_manisso : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://github.com/Manisso"
        date = "2021-01-10"
        comment = "Phishing Kit - Facebook - 'By Manisso'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "login.php"
        $spec_file2 = "fb.php"
        $spec_file3 = "robots.txt"
        $spec_file4 = ".htaccess"
        $spec_file5 = "finish.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}