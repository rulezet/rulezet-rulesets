rule PK_Adobe_RD2 : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe "
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-06"
        comment = "Phishing Kit - Adobe - 'cReAtEd By VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "index.html"
        $spec_file4 = "adobe1.png"
        $spec_file5 = "adobe1-w.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}