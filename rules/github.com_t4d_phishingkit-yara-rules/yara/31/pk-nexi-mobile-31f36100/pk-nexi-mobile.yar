rule PK_Nexi_mobile : Nexi
{
    meta:
        description = "Phishing Kit impersonating Nexi (Nexi Pay)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-24"
        comment = "Phishing Kit - Nexi"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "pannello2"
        $spec_dir2 = "database"
                $spec_file = "carta.php"
        $spec_file2 = "key6.php"
        $spec_file3 = "ajaxstat.php"
        $spec_file4 = "VendorsTest_tmp.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}