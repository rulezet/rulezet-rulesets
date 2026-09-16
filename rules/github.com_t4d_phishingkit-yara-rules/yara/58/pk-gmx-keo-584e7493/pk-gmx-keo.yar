rule PK_GMX_keo : GMX
{
    meta:
        description = "Phishing Kit - impersonating GMX"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-10"
        comment = "Phishing Kit - GMX - using file like keokeo"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Mobile Login1_files"
        $spec_dir1 = "Mobile Login_files"
                $spec_file = "1.php"
        $spec_file2 = "2.php"
        $spec_file3 = "index2.html"
        $spec_file4 = "pl-m-frame-asp.html"
        $spec_file5 = "gmx_banner_mailapp_android_v3.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}