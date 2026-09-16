rule PK_Payeer_joss : Payeer
{
    meta:
        description = "Phishing Kit impersonating Payeer"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-29"
        comment = "Phishing Kit - Payeer - 'joss.txt'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "PAYEER_files"
                $spec_file = "4.php"
        $spec_file2 = "Incorrect.html"
        $spec_file3 = "Incorrect-2fa.html"
        $spec_file4 = "enterprise.js.download"
        $spec_file5 = "saved_resource.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}