rule PK_WellsFargo_Rebaiamar : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-05"
        comment = "Phishing Kit - Wells Fargo - by 'skype :rebaiamar'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "change-email.txt"
        $spec_file2 = "sand_login.php"
        $spec_file3 = "sand_email.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}