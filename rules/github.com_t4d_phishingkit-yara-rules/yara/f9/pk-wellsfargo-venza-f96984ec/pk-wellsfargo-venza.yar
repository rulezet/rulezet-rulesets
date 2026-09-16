rule PK_WellsFargo_venza : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-25"
        comment = "Phishing Kit - Wells Fargo - 'CrEaTeD bY VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "email.php"
        $spec_file2 = "parse.php"
        $spec_file3 = "wf-fonts.css"
        $spec_file4 = "WF_stagecoach_rgb_ylw_F1.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}