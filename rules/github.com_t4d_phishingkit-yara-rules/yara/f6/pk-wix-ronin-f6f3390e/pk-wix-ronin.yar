rule PK_Wix_ronin : Wix
{
    meta:
        description = "Phishing Kit impersonating Wise.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-29"
        comment = "Phishing Kit - Wix - 'From: sifur@shadow.ronin'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "login.html"
        $spec_file2 = "lynx.php"
        $spec_file3 = "auth.html"
        $spec_file4 = "mod.PNG"
        $spec_file5 = "download.png"
        $spec_file6 = "app.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}