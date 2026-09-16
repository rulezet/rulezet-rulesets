rule PK_WellsFargo_spox : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-09"
        comment = "Phishing Kit - Wells Fargo - 'C0d3d by Spox_dz'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Spox"
        $spec_dir2 = "Wells_result"
                $spec_file = "config.php"
        $spec_file2 = "Bin_API.php"
        $spec_file3 = "Mail5.php"
        $spec_file4 = "Contact_information.php"
        $spec_file5 = "Security_Question.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}