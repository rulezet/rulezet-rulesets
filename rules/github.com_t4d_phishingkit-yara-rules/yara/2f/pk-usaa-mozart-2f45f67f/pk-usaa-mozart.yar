rule PK_USAA_mozart : USAA
{
    meta:
        description = "Phishing Kit impersonating USAA Savings Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-06"
        comment = "Phishing Kit - USAA - with a 'mozart' directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mozart"
        $spec_dir2 = "grabber"
        $spec_dir3 = "logs"
                $spec_file = "re_onetime.html"
        $spec_file2 = "onetime.php"
        $spec_file3 = "session_relogin.php"
        $spec_file4 = "9C7F15704715916A9.woff2"
        $spec_file5 = "ent-unified-logon-web.ce50f064965f72792379.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}