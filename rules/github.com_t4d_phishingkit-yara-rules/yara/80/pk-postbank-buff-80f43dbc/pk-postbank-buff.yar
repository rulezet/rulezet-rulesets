rule PK_Postbank_buff : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-06-04"
        comment = "Phishing Kit - Postbank - 'ini_set(output_buffering,4096)'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Postbank Banking & Brokerage-Dateien"
        $spec_dir1 = "danke-Dateien"
        $spec_dir2 = "BOTS"
                $spec_file = "Postbank Banking & Brokerage.htm"
        $spec_file2 = "passwort.php"
        $spec_file3 = "params.php"
        $spec_file4 = "ccadd.php"
        $spec_file5 = "pbbg.94a99b13acbdc92b.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}