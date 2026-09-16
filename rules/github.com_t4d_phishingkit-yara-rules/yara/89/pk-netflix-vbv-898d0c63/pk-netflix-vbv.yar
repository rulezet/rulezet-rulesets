rule PK_Netflix_VBV : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-20"
        comment = "Phishing Kit - Netflix - using '_XVBVX_.php' script"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "nfx"
                $spec_file = "__CONFIG__.php"
        $spec_file2 = "Warning.php"
        $spec_file3 = "sayron.php"
        $spec_file4 = "_XVBVX_.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                 all of ($spec_file*)
}