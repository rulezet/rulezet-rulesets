rule PK_AdobePDF_antenna : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Adobe PDF Online - contain antenna.css file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "core"
                $spec_file = "antenna.css"
        $spec_file2 = "screenshot_23.png"
        $spec_file3 = "fx.js"
        $spec_file4 = "post.php"
        $spec_file5 = "22222222222.png"
        $spec_file6 = "gh-adobe-impersonation-scam-loginwindow.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}