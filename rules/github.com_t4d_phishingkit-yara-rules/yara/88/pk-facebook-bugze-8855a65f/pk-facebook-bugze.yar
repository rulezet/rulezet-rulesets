rule PK_Facebook_bugze : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook help center"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-02"
        comment = "Phishing Kit - Facebook - 'CC: mr.bugze@gmail.com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "form"
        $spec_dir2 = "Confirm Personal Information _ Facebook Help Center_files"
                $spec_file = "upload.php"
        $spec_file2 = "step3.php"
        $spec_file3 = "222.php"
        $spec_file4 = "5.png"
        $spec_file5 = "identity.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}