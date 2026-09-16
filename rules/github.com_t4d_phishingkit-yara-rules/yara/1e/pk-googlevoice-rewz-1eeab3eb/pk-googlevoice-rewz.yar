rule PK_GoogleVoice_rewz : GoogleVoice
{
    meta:
        description = "Phishing Kit impersonating Google Voice service"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-12"
        comment = "Phishing Kit - Google Voice - 'From: REWZ@$server'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "index_0f_invalid.php"
        $spec_file2 = "index_other.php"
        $spec_file3 = "rewz_cod.php"
        $spec_file4 = "rewz_other_invalid.php"
        $spec_file5 = "klik.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}