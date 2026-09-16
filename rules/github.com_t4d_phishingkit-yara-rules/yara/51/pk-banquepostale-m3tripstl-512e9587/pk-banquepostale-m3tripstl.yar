rule PK_BanquePostale_m3tripstl : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-23"
        comment = "Phishing kit - Banque Postale - 'postal infos By METRI'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Pstl_files"
        $spec_dir1 = "M3tri-hash-bots"
                $spec_file = "anti9.php"
        $spec_file2 = "Error.php"
        $spec_file3 = "pstl-rd-otp.php"
        $spec_file4 = "pstl-done.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}