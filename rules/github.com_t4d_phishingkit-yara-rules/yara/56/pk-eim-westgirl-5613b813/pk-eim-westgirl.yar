rule PK_EIM_westgirl : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat Internet Mail (EIM)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-19"
        comment = "Phishing Kit - Etisalat - 'WeStGiRl'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "login_files"
                $spec_file = "login.htm"
        $spec_file2 = "dojo.js"
        $spec_file3 = "west.php"
        $spec_file4 = "a.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}