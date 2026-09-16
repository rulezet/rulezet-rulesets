rule PK_Rafidain_robot : Rafidain
{
    meta:
        description = "Phishing Kit impersonating Rafidain Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-01"
        comment = "Phishing Kit - Rafidain - '$recipient_email = robot@rafidain-bank.online'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "uploadDir"
        $spec_dir2 = "uploads"

                $spec_file = "login.html"
        $spec_file2 = "process3.php"
        $spec_file3 = "scc3.css"
        $spec_file4 = "page2.html"
        $spec_file5 = "long.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}