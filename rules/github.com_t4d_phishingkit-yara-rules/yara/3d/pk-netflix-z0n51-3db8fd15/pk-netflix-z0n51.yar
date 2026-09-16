rule PK_Netflix_z0n51 : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-02"
        comment = "Phishing Kit - Netflix - z0n51 directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "inc"
        $spec_dir2 = "z0n51/"
                $spec_file = "fbbb.png"
        $spec_file2 = "ss.php"
        $spec_file3 = "details.php"
        $spec_file4 = "app.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}