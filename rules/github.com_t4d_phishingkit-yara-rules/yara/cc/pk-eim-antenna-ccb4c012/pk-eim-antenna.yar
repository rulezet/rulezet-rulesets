rule PK_EIM_antenna : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat Internet Mail (EIM)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Etisalat - contain antenna.css file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "core"
                $spec_file = "antenna.css"
        $spec_file2 = "fx.js"
        $spec_file3 = "post.php"
        $spec_file4 = "screenshot_2.png"
        $spec_file5 = "screenshot_3.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}