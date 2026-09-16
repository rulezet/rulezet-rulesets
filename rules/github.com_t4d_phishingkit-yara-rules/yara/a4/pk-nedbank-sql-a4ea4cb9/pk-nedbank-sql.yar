rule PK_Nedbank_sql : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-11"
        comment = "Phishing Kit - Nedbank - using SQLite database"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "scripts"
        $spec_dir2 = "phpliteadmin"
                $spec_file = "NedbankMoney.htm"
        $spec_file2 = "read.php"
        $spec_file3 = "NedMoney~ATMCARDS~LIMITS.htm"
        $spec_file4 = "NedbankLogin_v7.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}