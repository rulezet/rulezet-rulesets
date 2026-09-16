rule PK_1and1_Ionos_mademen : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-13"
        comment = "Phishing Kit - IONOS - 'MADEMEN CYBER TEAM'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "demo_files"
                $spec_file = "demp.php"
        $spec_file2 = "go.php"
        $spec_file3 = "err.php"
        $spec_file4 = "load.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}