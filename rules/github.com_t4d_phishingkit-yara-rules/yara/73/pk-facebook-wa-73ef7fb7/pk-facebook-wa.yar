rule PK_Facebook_wa : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-25"
        comment = "Phishing Kit - Facebook - using WhatsApp page"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "etc"
        $spec_dir2 = "setting"
                $spec_file = "visitor.json"
        $spec_file1 = "antispam.json"
        $spec_file2 = "data.json"
        $spec_file3 = "data.php"
        $spec_file4 = "check.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}