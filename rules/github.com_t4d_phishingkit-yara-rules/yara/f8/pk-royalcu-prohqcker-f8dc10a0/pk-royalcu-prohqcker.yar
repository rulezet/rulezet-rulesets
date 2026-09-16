rule PK_RoyalCU_prohqcker : RoyalCU
{
    meta:
        description = "Phishing Kit impersonating Royal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-30"
        comment = "Phishing Kit - Royal Credit Union - 'Telegram ID: @prohqcker *Royal CU'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "js"
                $spec_file = "personal.html"
        $spec_file2 = "db_connect4.php"
        $spec_file3 = "c.html"
        $spec_file4 = "me.php"
        $spec_file5 = "01516-logo-lg-md-publish.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}