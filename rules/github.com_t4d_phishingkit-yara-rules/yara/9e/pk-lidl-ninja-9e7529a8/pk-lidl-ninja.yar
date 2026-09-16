rule PK_LIDL_ninja : LIDL
{
    meta:
        description = "Phishing Kit impersonating LIDL"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2025-02-16"
        comment = "Phishing Kit - LIDL - using ninja.jpg file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "index.php"
        $spec_file2 = "autocuisseur.jpg"
        $spec_file3 = "bouilloire.jpg"
        $spec_file4 = "lidl.png"
        $spec_file5 = "ninja.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}