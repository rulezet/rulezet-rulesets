rule PK_BanquePostale_z0n51_2 : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-27"
        comment = "Phishing kit - Banque Postale - 'Author: z0n51'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir1 = "sass"
                $spec_file = "loading11.php"
        $spec_file2 = "failed_login.php"
        $spec_file3 = "certicode.php"
        $spec_file4 = "certicode.png"
        $spec_file5 = "secure-asterisk.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}