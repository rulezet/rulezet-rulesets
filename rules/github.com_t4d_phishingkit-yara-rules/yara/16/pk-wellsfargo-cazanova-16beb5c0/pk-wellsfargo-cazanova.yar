rule PK_WellsFargo_cazanova : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-08"
        comment = "Phishing Kit - Wells Fargo - 'config[sess_cookie_name] = cazanova"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "sycho"
        $spec_dir2 = "views"
                $spec_file = "CodeIgniter.php"
        $spec_file2 = "sitekey.php"
        $spec_file3 = "homepage-horz-logo.svg"
        $spec_file4 = "2.js"
        $spec_file5 = "2134651.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}