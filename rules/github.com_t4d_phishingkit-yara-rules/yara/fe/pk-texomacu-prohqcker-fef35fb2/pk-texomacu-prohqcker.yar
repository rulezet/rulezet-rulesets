rule PK_TexomaCU_prohqcker : TexomaCU
{
    meta:
        description = "Phishing Kit impersonating Texoma Community Credit Union "
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-12"
        comment = "Phishing Kit - TexomaCU - '**Prohqcker*TC***+++'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "file"
        $spec_dir2 = "images"
                $spec_file = "me.php"
        $spec_file2 = "c.html"
        $spec_file3 = "prohqcker3.php"
        $spec_file4 = "personal.html"
        $spec_file5 = "logo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}