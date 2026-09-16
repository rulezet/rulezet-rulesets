rule PK_Telstra_mengunjungi : Telstra
{
    meta:
        description = "Phishing Kit impersonating Telstra"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-06"
        comment = "Phishing Kit - Telstra - 'Mengunjungi Scampage'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "manage"
        $spec_dir2 = "file"
        $spec_dir3 = "wait"
                $spec_file = "07-nikosx7.php"
        $spec_file2 = "dest5.html"
        $spec_file3 = "block3.php"
        $spec_file4 = "log3.css"
        $spec_file5 = "mag2.css"
        $spec_file6 = "gov-canada-logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}