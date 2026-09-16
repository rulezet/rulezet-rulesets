rule PK_NFCU_surf : NFCU
{
    meta:
        description = "Phishing Kit impersonating Navy Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-06"
        comment = "Phishing Kit - NFCU - 'Location: surf2.php'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "need3.php"
        $spec_file2 = "surf5.php"
        $spec_file3 = "nv.gif"
        $spec_file4 = ".htaccess"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                 all of ($spec_file*)
}