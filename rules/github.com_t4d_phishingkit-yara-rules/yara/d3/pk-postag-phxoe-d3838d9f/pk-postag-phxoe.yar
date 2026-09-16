rule PK_PostAG_phxoe : PostAG
{
    meta:
        description = "Phishing Kit impersonating PostAG Austria"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-05"
        comment = "Phishing Kit - PostAG - '$_POST[phxoe]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "LoginServices"
        $spec_dir1 = "main"
                $spec_file = "umzug.php"
        $spec_file2 = "snd3d.php"
        $spec_file3 = "sndcrd.php"
        $spec_file4 = "3D.php"
        $spec_file5 = "box.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}