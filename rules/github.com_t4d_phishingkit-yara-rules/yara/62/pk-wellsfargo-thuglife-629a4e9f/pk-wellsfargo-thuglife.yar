rule PK_WellsFargo_Thuglife : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-06"
        comment = "Phishing Kit - Wells Fargo - '!Thuglife_Legend+ !'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "nens.php"
        $spec_file2 = "nnew.htm"
        $spec_file3 = "slout.php"
        $spec_file4 = "tons.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}