rule PK_SocieteGenerale_dib : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-11"
        comment = "Phishing Kit - Societe Generale - 'Author : DIB'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "index_files"
        $spec_dir1 = "sms_files"
        $spec_file1 = "pictos-fonctionnels_20200629183129.svg"
        $spec_file2 = "filter.php"
        $spec_file3 = "pass.php"
        $spec_file4 = "funcs.php"
        $spec_file5 = "cart.php"
        $spec_file6 = "tel.php"
        $spec_file7 = "sms.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}