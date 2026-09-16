rule PK_WellsFargo_mky : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - Wells Fargo - 'CREATED BY MkY'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Scv"
        $spec_dir2 = "CrawlerDetect"
        $spec_dir3 = "Os"
                $spec_file = "alert.php"
        $spec_file2 = "Botsettings.ini"
        $spec_file3 = "Aemail.php"
        $spec_file4 = "Setmodule.php"
        $spec_file5 = "SendModule.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}