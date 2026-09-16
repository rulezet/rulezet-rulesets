rule PK_WellsFargo_yochi : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-27"
        comment = "Phishing Kit - Wells Fargo - '@yo_chi'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "admin"
        $spec_dir2 = "config"
        $spec_dir3 = "home"
                $spec_file = "prl.php"
        $spec_file2 = "live.json"
        $spec_file3 = "infile.php"
        $spec_file4 = "rando.php"
        $spec_file5 = "wf_logo_220x23.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}