rule PK_Facebook_kasroudra : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-21"
        comment = "Phishing Kit - Facebook - 'Copyright (c) 2021 KasRoudra'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "LICENSE"
        $spec_file1 = "login.html"
        $spec_file2 = "mobile.html"
        $spec_file3 = "hsts-pixel.gif"
        $spec_file4 = "script.js"
        $spec_file5 = "README.md"
        $spec_file6 = "logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
                all of ($spec_file*)
}