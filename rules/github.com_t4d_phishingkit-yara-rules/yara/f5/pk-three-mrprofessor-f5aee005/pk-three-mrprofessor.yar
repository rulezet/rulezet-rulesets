rule PK_Three_mrprofessor : Three
{
    meta:
        description = "Phishing Kit impersonating Three.co.uk"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-21"
        comment = "Phishing Kit - Three - 'Scampage by MrProfessor'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "My3Login_data"
                $spec_file = "fg.php"
        $spec_file2 = "lg.php"
        $spec_file3 = "CONTROLS.php"
        $spec_file4 = "My3Login.html"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}