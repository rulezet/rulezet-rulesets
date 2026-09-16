rule PK_Roundcube_rc : Roundcube
{
    meta:
        description = "Phishing Kit impersonating Roundcube login"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-07"
        comment = "Phishing Kit - Roundcube - '$_user | RC'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "roundcube.html"
        $spec_file2 = "roundcube.php"
        $spec_file3 = "port.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}