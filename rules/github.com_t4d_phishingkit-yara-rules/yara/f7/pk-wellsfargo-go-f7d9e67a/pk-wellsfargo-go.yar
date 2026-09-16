rule PK_WellsFargo_go : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-20"
        comment = "Phishing Kit - Wells Fargo - using several 'go' files"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "go_files"
                $spec_file = "go.htm"
        $spec_file2 = "go.php"
        $spec_file3 = "login-userprefs.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}