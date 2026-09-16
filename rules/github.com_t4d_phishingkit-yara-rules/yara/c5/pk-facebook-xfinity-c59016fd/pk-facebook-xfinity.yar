rule PK_Facebook_xfinity : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Facebook - '= xfinity login info ='"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "image"
                $spec_file = "valid-Card.php"
        $spec_file2 = "sdewewe images (4).jpeg"
        $spec_file3 = "xfinity.svg"
        $spec_file4 = "creadit-card.php"
        $spec_file5 = "choose-an-option.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}