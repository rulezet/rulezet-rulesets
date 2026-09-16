rule PK_WellsFargo_genius : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-13"
        comment = "Phishing Kit - Wells Fargo - '!Genius231_Legend+ !"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "index.htm"
        $spec_file2 = "iBass.php"
        $spec_file3 = "SLim.php"
        $spec_file4 = "wewewe.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}