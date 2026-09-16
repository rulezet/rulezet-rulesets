rule PK_BanquePostale_fnetwork : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-30"
        comment = "Phishing kit - Banque Postale - 'BY Mr.fnetwork'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "oklm"
        $spec_dir1 = "z0n51"
                $spec_file = "mise_a_jour_Certicode.php"
        $spec_file2 = "certicode.png"
        $spec_file3 = "details.php"
        $spec_file4 = "ss.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}