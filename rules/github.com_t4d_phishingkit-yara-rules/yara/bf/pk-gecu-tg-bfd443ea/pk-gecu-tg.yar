rule PK_GECU_tg : GECU
{
    meta:
        description = "Phishing Kit impersonating GECU Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-20"
        comment = "Phishing Kit - GECU - exfil with Telegram"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "gecu_files"
        $spec_dir2 = "actions"
                $spec_file = "ii.php"
        $spec_file2 = "lgn.php"
        $spec_file3 = "telegram.php"
        $spec_file4 = "geculogo_200px75px-AxzG4.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}