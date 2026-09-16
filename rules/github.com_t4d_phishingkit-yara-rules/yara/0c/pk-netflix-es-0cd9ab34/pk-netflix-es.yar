rule PK_Netflix_es : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-07-31"
        comment = "Phishing Kit - Netflix - with spanish material"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "auth"
        $spec_dir2 = "secure"
        $spec_dir3 = "CSS"
                $spec_file = "gg.php"
        $spec_file2 = "nn.php"
        $spec_file3 = "cc.php"
        $spec_file4 = "phone.php"
        $spec_file5= "nficon2016.ico"
        $spec_file6 = "otSDKStub.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}