rule PK_1and1_Ionos_onlyone : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing Kit - 1and1 - 'By The Only One'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "img"
        $spec_dir2 = ".well-known"
                $spec_file = "inpagelayer.css"
        $spec_file2 = "apple-touch-icon.png"
        $spec_file3 = "index.html"
        $spec_file4 = "login.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}