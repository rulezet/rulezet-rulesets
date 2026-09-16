rule PK_NBTbank_packaging : NBTbank
{
    meta:
        description = "Phishing Kit impersonating NBTbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-22"
        comment = "Phishing Kit - NBTbank - 'From: Packaging'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "img"
                $spec_file = "db_connect5.php"
        $spec_file2 = "index2.html"
        $spec_file3 = "security.html"
        $spec_file4 = "BANGOR.png"
        $spec_file5 = "RadDockableObject.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_dir*) and
        all of ($spec_file*)
}