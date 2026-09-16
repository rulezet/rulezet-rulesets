rule PK_FifthThirdBank_b64 : FifthThirdBank
{
    meta:
        description = "Phishing Kit impersonating Fifth Third Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-23"
        comment = "Phishing Kit - Fifth Third Bank - Base64 obfuscation used on PHP files"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Cm"
        $spec_dir2 = "signal"
                $spec_file = "indexem.php"
        $spec_file2 = "grabber.php"
        $spec_file3 = "process3.php"
        $spec_file4 = "ng8.bundle.min.ffb4e1.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}