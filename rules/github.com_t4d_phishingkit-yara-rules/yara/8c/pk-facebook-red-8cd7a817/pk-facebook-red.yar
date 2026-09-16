rule PK_Facebook_red : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-11"
        comment = "Phishing Kit - Facebook - 'const red__'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "recp"
        $spec_dir2 = "img"
                $spec_file = "auth.htm"
        $spec_file1 = "mlogin.html"
        $spec_file2 = "config.js"
        $spec_file3 = "fbDlm.css"
        $spec_file4 = "wasap.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}