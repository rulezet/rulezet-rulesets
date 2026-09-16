rule PK_WellsFargo_RD265 : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-16"
        comment = "Phishing Kit - Wells Fargo - using RD265 in archive name - reference to 'venza'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "card.html"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "detail.html"
        $spec_file5 = "WF_stagecoach_rgb_ylw_F1.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}