rule PK_Zimbra_3870 : Zimbra
{
    meta:
        description = "Phishing Kit impersonating Zimbra login page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-16"
        comment = "Phishing Kit - Zimbra - several files contain '3870' string in names"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "harmony"
        $spec_dir2 = "submit"
        $spec_file = "hotmail.php"
        $spec_file2 = "LoginBanner_white3870.png"
        $spec_file3 = "ImgNewSelectPullDownArrow3870.png"
        $spec_file4 = "zimbra3870.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}