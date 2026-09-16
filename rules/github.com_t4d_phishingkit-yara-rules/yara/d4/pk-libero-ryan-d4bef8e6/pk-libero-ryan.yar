rule PK_Libero_ryan : Libero
{
    meta:
        description = "Phishing Kit impersonating Libero Italy"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-04"
        comment = "Phishing Kit - Libero - 'rYan@LIBERO.IT 2023 UPDATE LOGIN INFO'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "get_pass.php"
        $spec_file2 = "signin.php"
        $spec_file3 = "core-it.js"
        $spec_file4 = "logo-buonissimo.png"
        $spec_file5 = "libero_favicon.ico"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}