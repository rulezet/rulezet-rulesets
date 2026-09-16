rule PK_Liberbank_shanks : Liberbank
{
    meta:
        description = "Phishing Kit impersonating Liberbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-28"
        comment = "Phishing Kit - Liberbank - 'From: SHANkS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "killua"
        $spec_dir2 = "assets"
                $spec_file = "Elk.php"
        $spec_file2 = "aek.php"
        $spec_file3 = "ccn.php"
        $spec_file4 = "ced2.php"
        $spec_file5 = "social.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}