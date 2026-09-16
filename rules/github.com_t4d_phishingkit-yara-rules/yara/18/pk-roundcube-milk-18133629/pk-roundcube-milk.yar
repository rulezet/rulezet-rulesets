rule PK_Roundcube_milk : Roundcube
{
    meta:
        description = "Phishing Kit impersonating Roundcube login"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-01-02"
        comment = "Phishing Kit - Roundcube - '@author milk'"

    strings:
                $zip_file = { 50 4b 03 04 }

        $spec_dir = "roundcube_files"
                $spec_file = "verif.html"
        $spec_file2 = "login.php"
        $spec_file3 = "xskin.min.js.download"
        $spec_file4 = "jstz.min.js.download"
        $spec_file5 = "roundcube_logo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}