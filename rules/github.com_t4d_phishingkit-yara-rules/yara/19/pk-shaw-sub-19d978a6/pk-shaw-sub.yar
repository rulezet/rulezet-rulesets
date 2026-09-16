rule PK_Shaw_sub : Shaw
{
    meta:
        description = "Phishing Kit impersonating Shaw.ca"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-15"
        comment = "Phishing Kit - Shaw - using sub.txt to write data"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "icons"
                $spec_file = "card.php"
        $spec_file2 = "infper.php"
        $spec_file3 = "infcar.php"
        $spec_file4 = "login-form.shaw.js"
        $spec_file5 = "info.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}