rule PK_WellsFargo_sm : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-31"
        comment = "Phishing Kit - Wells Fargo - '----sm----'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "entiti"
                $spec_file = "shakeppfl.css"
        $spec_file2 = "wellsfarrgo.html"
        $spec_file3 = "id.html"
        $spec_file4 = "wells1.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}