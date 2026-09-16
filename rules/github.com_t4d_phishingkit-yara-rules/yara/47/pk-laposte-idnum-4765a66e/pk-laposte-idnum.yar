rule PK_LaPoste_idnum : LaPoste
{
    meta:
        description = "Phishing Kit impersonating La Poste FR - identite numerique"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-14"
        comment = "Phishing Kit - LaPoste - identite numerique"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "act"
                $spec_file = "rs.txt"
        $spec_file2 = "refresh.php"
        $spec_file3 = "zbs.php"
        $spec_file4 = "getphone.php"
        $spec_file5 = "info.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}