rule PK_Facebook_ditznesia : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-05"
        comment = "Phishing Kit - Facebook - 'Copyright © Ditznesia'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "data"
        $spec_dir2 = "ditznesia"
                $spec_file = "visitor.json"
        $spec_file1 = "final.php"
        $spec_file2 = "UpdateData.php"
        $spec_file3 = "data.json"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}