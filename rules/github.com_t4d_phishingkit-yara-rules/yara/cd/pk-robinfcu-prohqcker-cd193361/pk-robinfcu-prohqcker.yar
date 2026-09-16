rule PK_RobinFCU_prohqcker : RobinFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-15"
        comment = "Phishing Kit - Robins Federal Credit Union - '*@Prohqcker_Bot**Robins Financial*'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "js"
                $spec_file = "personal.html"
        $spec_file2 = "prohqcker5.php"
        $spec_file3 = "c.html"
        $spec_file4 = "me.php"
        $spec_file5 = "desktop-background-31261c4b72eb487c279e9a1b57d9f095.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}