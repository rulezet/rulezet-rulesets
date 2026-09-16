rule PK_Facebook_checks : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-17"
        comment = "Phishing Kit - Facebook - 'Facebook - emailchecks.io'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "handlers"
                $spec_file = "process.php"
        $spec_file2 = "bt.php"
        $spec_file3 = "email.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}