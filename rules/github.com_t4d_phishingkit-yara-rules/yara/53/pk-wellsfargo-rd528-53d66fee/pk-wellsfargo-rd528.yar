rule PK_WellsFargo_RD528 : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-19"
        comment = "Phishing Kit - Wells Fargo - using RD528 in archive name - reference to 'venza'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
                $spec_file = "rout.html"
        $spec_file2 = "parse.php"
        $spec_file3 = "email.php"
        $spec_file4 = "detail.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}