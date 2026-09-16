rule PK_Netflix_prohqcker : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-10-14"
        comment = "Phishing Kit - Netflix - using prohqcker.php file"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "prohqcker.php"
        $spec_file2 = "MASTERCARD@2x.png"
        $spec_file3 = "VERVE@2x.png"
        $spec_file4 = "simplicity.51df52c550778103fe46.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                 all of ($spec_file*)
}