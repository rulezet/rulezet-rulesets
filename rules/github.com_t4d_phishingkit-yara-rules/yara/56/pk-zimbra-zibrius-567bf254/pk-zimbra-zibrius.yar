rule PK_Zimbra_zibrius: Zimbra
{
    meta:
        description = "Phishing Kit impersonating Zimbra software"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-10"
        comment = "Phishing Kit - Zimbra - '$subject = zibrius'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
        $spec_file = "error2.html"
        $spec_file2 = "post.php"
        $spec_file3 = "stryg2.jpeg"
        $spec_file4 = "LoginBanner_white.png"
        $spec_file5 = "AppBanner_white.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}