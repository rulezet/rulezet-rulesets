rule PK_myCSS_bankai : myCSS
{
    meta:
        description = "Phishing Kit impersonating myCSS, a CSS.ch portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-18"
        comment = "Phishing kit - myCSS - use of 'bankai' named variables"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mycss-login"
        $spec_dir1 = "mycss-ch-ruckerstattungcodeanyappcom"
                $spec_file = "load-sms.php"
        $spec_file2 = "3dsec_2293842.html"
        $spec_file3 = "unknown_1835038.gif"
        $spec_file4 = "loadsms_3080281.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}